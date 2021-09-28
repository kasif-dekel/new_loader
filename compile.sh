rm -rf ./build/libloader.so
rm -rf ./build/libloaderudp.so
mkdir ./build
if [ $1 != 'udp' ]
then
    gcc main.c utils.c -o ./build/libloader.so -fPIC -shared -ldl -fcf-protection=none
else
    gcc main.c utils.c -o ./build/libloaderudp.so -fPIC -shared -ldl -fcf-protection=none -DIS_UDP
fi

#scp -i ~/.ssh/id_rsa_sensor ./build/libloader.so dbg@192.168.145.130:/home/dbg
#ssh -i ~/.ssh/id_rsa_sensor dbg@192.168.145.130 "sudo mv /home/dbg/libloader.so /opt/fuzzer"