# :: compile
clang -o analyze_so analyze_so.c
clang -o dump_so dump_so.c

mkdir .src; mv dump_so.c analyze_so.c $PWD/.src
echo "
./dump_so <file.so>      | dump .so file to .c
./analyze_so <file.so>   | analyze file
"
rm setup.sh

