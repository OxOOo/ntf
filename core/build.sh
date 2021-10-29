set -ex

bazel build --config=c++17 -c opt //main:server //main:client

OUT_PATH=bazel-out/k8-opt/bin
cp $OUT_PATH/main/server $OUT_PATH/main/client ./
