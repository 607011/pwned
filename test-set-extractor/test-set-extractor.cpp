/*
 Copyright © 2019 Oliver Lau <oliver@ersatzworld.net>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <iostream>
#include <fstream>
#include <string>

#include <boost/filesystem.hpp>
#include <boost/random/mersenne_twister.hpp>

#include <passwordhashandcount.hpp>
#include <passwordinspector.hpp>

int main(int argc, const char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: test-set-extractor <md5_count_input_file> <md5_count_output_file>" << std::endl;
        return EXIT_FAILURE;
    }
    const std::string &inputFilename = argv[1];
    const std::string &outputFilename = argv[2];
    const uint64_t N = 20000;
    const uint64_t size = boost::filesystem::file_size(inputFilename);
    const uint64_t offset = size / N;
    std::ifstream in(inputFilename, std::ios::binary);
    if (!in.is_open()) {
        std::cerr << "Cannot open " << inputFilename << std::endl;
        return EXIT_FAILURE;
    }
    std::ofstream out(outputFilename, std::ios::binary | std::ios::trunc);
    if (!out.is_open()) {
        std::cerr << "Cannot open " << outputFilename << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "Input file:  " << inputFilename << " (" << size << " bytes, offset = " << offset << ")" << std::endl
    << "Output file: " << outputFilename << std::endl;

    std::cout << "Selecting " << N << " present hashes ... " << std::endl;
    pwned::PHC phc;
    for (uint64_t pos = 0; pos < size; pos += offset) {
        const uint64_t idx = pos - pos % pwned::PHC::size;
        if (phc.read(in, idx)) {
            std::cout << phc.hash << " @ " << idx << std::endl;
            phc.dump(out);
        }
    }

    std::cout << "Selecting " << N << " non-existent hashes ... " << std::endl;
    boost::random::mt19937_64 gen;
    gen.seed(31337);
    pwned::PasswordInspector inspector(inputFilename);
    for (auto i = 0; i < N; ++i) {
        pwned::Hash hash(gen(), gen());
        pwned::PHC p = inspector.binsearch(hash);
        if (p.count == 0) {
            p.hash = hash;
            p.dump(out);
            std::cout << hash << " #" << i << std::endl;
        }
    }
    std::cout << std::endl << "Ready." << std::endl;
    return EXIT_SUCCESS;
}
