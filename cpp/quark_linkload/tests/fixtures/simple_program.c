// Plain, normally-compiled executable -- zero Quark awareness anywhere in
// this file. Stands in for "the developer's own program," compiled with no
// special build target (just add_executable), then sealed and loaded WHOLE
// (no symbol extraction, no source change) by quark_linkload_simple_test.cpp.
#include <stdio.h>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    FILE* f = fopen(argv[1], "w");
    if (!f) return 1;
    fprintf(f, "quark_linkload_simple_fixture_output");
    fclose(f);
    return 0;
}
