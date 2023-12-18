if RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
wasm-pack build --target web --no-default-features --features \
wasm -Z build-std=panic_abort,std; 
then
    echo "\nBuild success!"
    du -h pkg/proof_of_exploit_bg.wasm
else
    echo "\nBuild failed because of above error"
    exit 1
fi


if ! [ -z "$1" ]
then
    rm -rf $1/wasm
    mkdir $1/wasm
    cp -r pkg/. $1/wasm/
    rm $1/wasm/.gitignore
    rm $1/wasm/README.md
    echo "Updated the package at $1/wasm"
fi