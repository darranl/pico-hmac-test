/* Copyright 2023, Darran A Lofthouse
 *
 * This file is part of pico-hmac-test.
 *
 * pico-sha-test is free software: you can redistribute it and/or modify it under the terms 
 * of the GNU General Public License as published by the Free Software Foundation, either 
 * version 3 of the License, or (at your option) any later version.
 *
 * pico-sha-test is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with pico-sha-test.
 * If  not, see <https://www.gnu.org/licenses/>. 
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"

#include "util/binaryutil.h"
#include "util/hexutil.h"
#include "util/systick.h"
#include "security/hmac.h"

#include "pico-hmac-data.h"

void hmac_test(struct data_element *the_data)
{
    uint32_t raw_key_size = the_data->key_length / 2;
    char raw_key[raw_key_size];
    char *hex_key = the_data->hex_key;
    for (short byte = 0 ; byte < raw_key_size ; byte++)
    {
        raw_key[byte] = hex_to_char(&hex_key[byte * 2]);
    }

    uint32_t raw_data_length = the_data->data_length / 2;
    char raw_data[raw_data_length];
    char *hex_data = the_data->hex_data;
    for (short byte = 0 ; byte < raw_data_length ; byte++)
    {
        raw_data[byte] = hex_to_char(&hex_data[byte * 2]);
    }

    uint32_t mac[5];  // Placeholder for generated MAC.

    start_syst_counter();
    hmac_sha1(raw_key, raw_key_size, raw_data, raw_data_length, mac);
    uint32_t ticks = stop_syst_counter();

    char *expected_mac = the_data->mac;
    short mac_pos = 0;
    bool success = true;

    char digest_hex[9];
    digest_hex[8] = 0;
    //printf("\nMAC  = ");
    for (short i = 0; i < 5; i++)
    {
        uint32_t test_int = mac[i];
        uint32_to_hex_string(mac[i], digest_hex);
        for (short byte = 0 ; byte < 8 && success ; byte++)
        {
            char charOne = digest_hex[byte];
            char charTwo = expected_mac[mac_pos++];
            if (charOne != charTwo) {
                success = false;
            }
        }
    }

    printf("| %*d | %*s | %*d |\n", 5, the_data->test_number, 11, success ? "Pass" : "Fail", 15, ticks);
}


int main()
{
    stdio_init_all();

    printf("\n\n\nBegin HMAC-SHA-1 Testing\n\n");

    printf("+-------+-------------+-----------------+\n");
    printf("| Test  | Pass / Fail | Syst Tick Count |\n");
    printf("+-------+-------------+-----------------+\n");
    
    for (short test = 0; test < 4 ; test++ ) {
        struct data_element current_element = hmac_tests[test];
        hmac_test(&current_element);        
    }

    printf("+-------+-------------+-----------------+\n");
}

#ifdef LOG_DATA
void log_data(char * data, uint32_t length) {
    short word_pos = 4;
    short word_count = 0;

    printf("* * Data * * \n");
    char temp_hex[9];
    temp_hex[8] = 0;
    for (uint32_t i = 0 ; i < length ; i++) {
        uint32_t temp_byte = data[i];
        uint32_to_hex(temp_byte, temp_hex);
        printf("%s", &temp_hex[6]);
        word_pos = (word_pos + 1) % 4;
        if (word_pos == 0) {
            word_count = (word_count + 1) % 20;
            if (word_count == 0) {
                printf("\n");
            } else {
            printf(" ");                
            }
        }
    }

    printf("\n");
}
#endif

#ifdef LOG_ARRAY
void log_words(uint32_t * words) {
    char binary_result[32];    
    short this_row_count = 0;

    printf("\n\nBinary Output\n\n");
    for (uint32_t word_pos = 0 ; word_pos <= 79 ; word_pos++) {
        int_to_binary(words[word_pos], binary_result);

        for (short pos = 0 ; pos < 32 ; pos++) {
            putchar(binary_result[pos]);
            if ((pos + 1) % 8 == 0) {
                putchar(' ');
            }
        }

        this_row_count = (this_row_count + 1) % 4;
        if (this_row_count == 0) {
            printf("\n");
        }
    }
}
#endif
