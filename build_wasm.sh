# RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' cargo build --lib --release --no-default-features --features dep_wasm --target wasm32-unknown-unknown -Z build-std=panic_abort,std
# RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' wasm-pack build --target web . -Z build-std=panic_abort,std
# RUSTFLAGS='-C target-feature=+atomics,+bulk-memory' wasm-pack build --target web . -Z build-std=panic_abort,std
wasm-pack build --target web

du -h pkg/proof_of_exploit_bg.wasm

rm -rf /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm
mkdir /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm
cp -r pkg/. /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm/
rm /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm/.gitignore
rm /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm/README.md

rm -rf /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/node_modules/pox-wasm
mkdir /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/node_modules/pox-wasm
cp -r /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/public/pox-wasm/. /Users/sohamzemse/Workspace/opensource/personal/proof-of-exploit-stuff/frontend/pox-frontend/node_modules/pox-wasm
