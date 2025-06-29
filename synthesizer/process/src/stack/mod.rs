// Copyright (c) 2019-2025 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

mod authorization;
pub use authorization::*;

mod call;
pub use call::*;

mod finalize_registers;
pub use finalize_registers::*;

mod finalize_types;
pub use finalize_types::*;

mod register_types;
pub use register_types::*;

mod registers;
pub use registers::*;

mod authorize;
mod deploy;
mod evaluate;
mod execute;
mod helpers;

use crate::{CallMetrics, Process, Trace, cost_in_microcredits_v2};
use console::{
    account::{Address, PrivateKey},
    network::prelude::*,
    program::{
        Argument,
        Entry,
        EntryType,
        FinalizeType,
        Future,
        Identifier,
        Literal,
        Locator,
        Owner as RecordOwner,
        Plaintext,
        PlaintextType,
        ProgramID,
        Record,
        RecordType,
        RegisterType,
        Request,
        Response,
        Value,
        ValueType,
    },
    types::{Field, Group},
};
use snarkvm_ledger_block::{Deployment, Transaction, Transition};
use snarkvm_synthesizer_program::{
    CallOperator,
    Closure,
    Function,
    Instruction,
    Operand,
    Program,
    RegistersCircuit,
    RegistersSigner,
    RegistersTrait,
    StackTrait,
};
use snarkvm_synthesizer_snark::{Certificate, ProvingKey, UniversalSRS, VerifyingKey};

use aleo_std::prelude::{finish, lap, timer};
use indexmap::IndexMap;
#[cfg(feature = "locktick")]
use locktick::parking_lot::RwLock;
#[cfg(not(feature = "locktick"))]
use parking_lot::RwLock;
use rand::{CryptoRng, Rng};
use std::sync::{Arc, Weak};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

pub type Assignments<N> = Arc<RwLock<Vec<(circuit::Assignment<<N as Environment>::Field>, CallMetrics<N>)>>>;

#[derive(Clone)]
pub enum CallStack<N: Network> {
    Authorize(Vec<Request<N>>, PrivateKey<N>, Authorization<N>),
    Synthesize(Vec<Request<N>>, PrivateKey<N>, Authorization<N>),
    CheckDeployment(Vec<Request<N>>, PrivateKey<N>, Assignments<N>, Option<u64>, Option<u64>),
    Evaluate(Authorization<N>),
    Execute(Authorization<N>, Arc<RwLock<Trace<N>>>),
    PackageRun(Vec<Request<N>>, PrivateKey<N>, Assignments<N>),
}

impl<N: Network> CallStack<N> {
    /// Initializes a call stack as `Self::Evaluate`.
    pub fn evaluate(authorization: Authorization<N>) -> Result<Self> {
        Ok(CallStack::Evaluate(authorization))
    }

    /// Initializes a call stack as `Self::Execute`.
    pub fn execute(authorization: Authorization<N>, trace: Arc<RwLock<Trace<N>>>) -> Result<Self> {
        Ok(CallStack::Execute(authorization, trace))
    }
}

impl<N: Network> CallStack<N> {
    /// Returns a new and independent replica of the call stack.
    pub fn replicate(&self) -> Self {
        match self {
            CallStack::Authorize(requests, private_key, authorization) => {
                CallStack::Authorize(requests.clone(), *private_key, authorization.replicate())
            }
            CallStack::Synthesize(requests, private_key, authorization) => {
                CallStack::Synthesize(requests.clone(), *private_key, authorization.replicate())
            }
            CallStack::CheckDeployment(requests, private_key, assignments, constraint_limit, variable_limit) => {
                CallStack::CheckDeployment(
                    requests.clone(),
                    *private_key,
                    Arc::new(RwLock::new(assignments.read().clone())),
                    *constraint_limit,
                    *variable_limit,
                )
            }
            CallStack::Evaluate(authorization) => CallStack::Evaluate(authorization.replicate()),
            CallStack::Execute(authorization, trace) => {
                CallStack::Execute(authorization.replicate(), Arc::new(RwLock::new(trace.read().clone())))
            }
            CallStack::PackageRun(requests, private_key, assignments) => {
                CallStack::PackageRun(requests.clone(), *private_key, Arc::new(RwLock::new(assignments.read().clone())))
            }
        }
    }

    /// Pushes the request to the stack.
    pub fn push(&mut self, request: Request<N>) -> Result<()> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                // Check that the number of requests does not exceed the maximum.
                ensure!(
                    requests.len() < Transaction::<N>::MAX_TRANSITIONS,
                    "The number of requests in the authorization must be less than '{}'.",
                    Transaction::<N>::MAX_TRANSITIONS
                );
                // Push the request to the stack.
                requests.push(request)
            }
            CallStack::Evaluate(authorization) => authorization.push(request)?,
            CallStack::Execute(authorization, ..) => authorization.push(request)?,
        }
        Ok(())
    }

    /// Pops the request from the stack.
    pub fn pop(&mut self) -> Result<Request<N>> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                requests.pop().ok_or_else(|| anyhow!("No more requests on the stack"))
            }
            CallStack::Evaluate(authorization) => authorization.next(),
            CallStack::Execute(authorization, ..) => authorization.next(),
        }
    }

    /// Peeks at the next request from the stack.
    pub fn peek(&mut self) -> Result<Request<N>> {
        match self {
            CallStack::Authorize(requests, ..)
            | CallStack::Synthesize(requests, ..)
            | CallStack::CheckDeployment(requests, ..)
            | CallStack::PackageRun(requests, ..) => {
                requests.last().cloned().ok_or_else(|| anyhow!("No more requests on the stack"))
            }
            CallStack::Evaluate(authorization) => authorization.peek_next(),
            CallStack::Execute(authorization, ..) => authorization.peek_next(),
        }
    }
}

#[derive(Clone)]
pub struct Stack<N: Network> {
    /// The program (record types, structs, functions).
    program: Program<N>,
    /// A reference to the global stack map.
    stacks: Weak<RwLock<IndexMap<ProgramID<N>, Arc<Stack<N>>>>>,
    /// The mapping of closure and function names to their register types.
    register_types: IndexMap<Identifier<N>, RegisterTypes<N>>,
    /// The mapping of finalize names to their register types.
    finalize_types: IndexMap<Identifier<N>, FinalizeTypes<N>>,
    /// The universal SRS.
    universal_srs: UniversalSRS<N>,
    /// The mapping of function name to proving key.
    proving_keys: Arc<RwLock<IndexMap<Identifier<N>, ProvingKey<N>>>>,
    /// The mapping of function name to verifying key.
    verifying_keys: Arc<RwLock<IndexMap<Identifier<N>, VerifyingKey<N>>>>,
    /// The program address.
    program_address: Address<N>,
}

impl<N: Network> Stack<N> {
    /// Initializes a new stack, if it does not already exist, given the process and the program.
    pub fn new(process: &Process<N>, program: &Program<N>) -> Result<Self> {
        // Retrieve the program ID.
        let program_id = program.id();
        // Ensure the program does not already exist in the process.
        ensure!(!process.contains_program(program_id), "Program '{program_id}' already exists");
        // Ensure the program contains functions.
        ensure!(!program.functions().is_empty(), "No functions present in the deployment for program '{program_id}'");

        // Serialize the program into bytes.
        let program_bytes = program.to_bytes_le()?;
        // Ensure the program deserializes from bytes correctly.
        ensure!(program == &Program::from_bytes_le(&program_bytes)?, "Program byte serialization failed");

        // Serialize the program into string.
        let program_string = program.to_string();
        // Ensure the program deserializes from a string correctly.
        ensure!(program == &Program::from_str(&program_string)?, "Program string serialization failed");

        // Return the stack.
        Stack::initialize(process, program)
    }

    /// Returns the register types for the given closure or function name.
    #[inline]
    pub fn get_register_types(&self, name: &Identifier<N>) -> Result<&RegisterTypes<N>> {
        // Retrieve the register types.
        self.register_types.get(name).ok_or_else(|| anyhow!("Register types for '{name}' do not exist"))
    }

    /// Returns the register types for the given finalize name.
    #[inline]
    pub fn get_finalize_types(&self, name: &Identifier<N>) -> Result<&FinalizeTypes<N>> {
        // Retrieve the finalize types.
        self.finalize_types.get(name).ok_or_else(|| anyhow!("Finalize types for '{name}' do not exist"))
    }

    /// Inserts the proving key if the program ID is 'credits.aleo'.
    fn try_insert_credits_function_proving_key(&self, function_name: &Identifier<N>) -> Result<()> {
        // If the program is 'credits.aleo' and it does not exist yet, load the proving key directly.
        if self.program_id() == &ProgramID::from_str("credits.aleo")?
            && !self.proving_keys.read().contains_key(function_name)
        {
            // Load the 'credits.aleo' function proving key.
            let proving_key = N::get_credits_proving_key(function_name.to_string())?;
            // Insert the 'credits.aleo' function proving key.
            self.insert_proving_key(function_name, ProvingKey::new(proving_key.clone()))?;
        }
        Ok(())
    }
}

impl<N: Network> PartialEq for Stack<N> {
    fn eq(&self, other: &Self) -> bool {
        self.program == other.program
            && self.register_types == other.register_types
            && self.finalize_types == other.finalize_types
    }
}

impl<N: Network> Eq for Stack<N> {}

// A helper enum to avoid cloning stacks.
#[derive(Clone)]
pub(crate) enum StackRef<'a, N: Network> {
    // Self's stack.
    Internal(&'a Stack<N>),
    // An external stack.
    External(Arc<Stack<N>>),
}

impl<N: Network> Deref for StackRef<'_, N> {
    type Target = Stack<N>;

    fn deref(&self) -> &Self::Target {
        match self {
            StackRef::Internal(stack) => stack,
            StackRef::External(stack) => stack,
        }
    }
}
