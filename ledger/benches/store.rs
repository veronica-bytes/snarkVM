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

use console::prelude::*;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

use aleo_std_storage::StorageMode;

use snarkvm_ledger::{
    store::{BlockStore, helpers::memory::BlockMemory},
    test_helpers::TestChainBuilder,
};

type Network = console::network::MainnetV0;

// Helper method to benchmark serialization.
fn block_storage(c: &mut Criterion) {
    let rng = &mut TestRng::default();

    c.bench_function(&format!("BlockStore:insert"), |b| {
        b.iter_batched(
            || {
                let store = BlockStore::<Network, BlockMemory<Network>>::open(StorageMode::new_test(None)).unwrap();
                let mut builder = TestChainBuilder::new(rng);
                let blocks = builder.generate_blocks(100, rng);

                (store, blocks)
            },
            |(store, blocks)| {
                for block in blocks {
                    if let Err(err) = store.insert(&block) {
                        panic!("Failed to insert block at height {}: {err}", block.height());
                    }
                }
            },
            BatchSize::SmallInput,
        )
    });
    /*
    {
        c.bench_function(&format!("BlockStore::get_block"), |b| b.iter(|| store.get_block(&block.hash()).unwrap()));
    }*/
}

criterion_group! {
    name = storage;
    config = Criterion::default().sample_size(10);
    targets = block_storage
}

criterion_main!(storage);
