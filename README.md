# pico-hmac-test
Test program to create and verify numerous HMAC-SHA-1 calculations on a Raspberry Pi Pico

## Cloning the project.

Checkout the project using the following command:

    git clone --recurse-submodules https://github.com/darranl/pico-hmac-test.git

## Building the project.

This assmumes you have already set up a working environment based on the [Getting Started with Pico](https://datasheets.raspberrypi.com/pico/getting-started-with-pico.pdf) documentation at [raspberrypi.com](https://www.raspberrypi.com).

    cd pico-hmac-test
    mkdir build
    cd build
    cmake ..
    make -j4

After this there will be two binaries which can be installed depending on your installation mechanism `pico-hmac-test.elf` or `pico-hmac-test.uf2`.

Once installed the test program runs immidiately and outputs the results to `stdio`.

e.g.
    Begin HMAC-SHA-1 Testing

    +-------+-------------+-----------------+
    | Test  | Pass / Fail | Syst Tick Count |
    +-------+-------------+-----------------+
    |     1 |        Pass |           53320 |
    |     2 |        Pass |           45031 |
    |     3 |        Pass |           65814 |
    |     4 |        Pass |           44392 |
    +-------+-------------+-----------------+


