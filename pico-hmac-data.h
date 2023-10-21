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

#include <stdlib.h>

struct data_element {
    short test_number;
    char *hex_key;
    uint32_t key_length;
    char *hex_data;
    uint32_t data_length;
    char *mac;
};

struct data_element hmac_tests[] = {
    {1, 
     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F", 
     128, 
     "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E", 
     68, 
     "5FD596EE78D5553C8FF4E72D266DFD192366DA29"},
    {2, 
     "000102030405060708090A0B0C0D0E0F10111213", 
     40, 
     "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E", 
     68, 
     "4C99FF0CB1B31BD33F8431DBAF4D17FCD356A807"},
    {3, 
     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F60616263", 
     200, 
     "53616D706C65206D65737361676520666F72206B65796C656E3D626C6F636B6C656E", 
     68, 
     "2D51B2F7750E410584662E38F133435F4C4FD42A"},
    {4, 
     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30", 
     98, 
     "53616D706C65206D65737361676520666F72206B65796C656E3C626C6F636B6C656E2C2077697468207472756E636174656420746167", 
     108, 
     "FE3529565CD8E28C5FA79EAC9D8023B53B289D96"}          
};