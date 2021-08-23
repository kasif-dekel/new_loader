rm -rf ./build
mkdir ./build
gcc main.c -o ./build/libloader.so -fPIC -shared -ldl
#scp -i ~/.ssh/id_rsa_sensor ./build/libloader.so dbg@192.168.145.130:/home/dbg
#ssh -i ~/.ssh/id_rsa_sensor dbg@192.168.145.130 "sudo mv /home/dbg/libloader.so /opt/fuzzer"