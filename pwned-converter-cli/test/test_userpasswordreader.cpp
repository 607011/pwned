/*
 Copyright © 2019 Oliver Lau <ola@ct.de>, Heise Medien GmbH & Co. KG - Redaktion c't

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

#define BOOST_TEST_MODULE test userpasswordreader
#define BOOST_TEST_MODULE_USERPASSWORDREADER

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <boost/test/unit_test.hpp>
#include "../userpasswordreader.hpp"

BOOST_AUTO_TEST_SUITE(test_userpasswordreader)

BOOST_AUTO_TEST_CASE(test_userpasswordreader_password_only_crlf)
{
  std::stringstream input;
  input << "1999kpi\r\n"
           "adminadminadmin\r\n"
           "rootadmin\r\n"
           "admin\r\n"
           "LOLOLOWKA\r\n"
           "bananek1\r\n"
           "alex123x\r\n"
           "jek295\r\n"
           "arigato559669\r\n"
           "Admin\r\n"
           "usipusi123\r\n"
           "Mata\r\n"
           "lololo123\r\n"
           "<password>\r\n"
           "13rfrfle\r\n"
           "bananek1\r\n"
           "root\r\n"
           "123123\r\n"
           "craft123\r\n"
           "opensite\r\n"
           "w334455\r\n"
           "gfgrf123\r\n"
           "Lomat222\r\n"
           "LeoPlay123\r\n"
           "sasha2006\r\n"
           "bananek1\r\n"
           "danila2005\r\n"
           "89277800752\r\n"
           "iopGhJ678%\r\n"
           "as527752\r\n"
           "polozyura1\r\n"
           "Leonidova2003\r\n"
           "bonjour\r\n"
           "20031512\r\n";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{});
  const std::vector<std::string> hashes{
    "da83e82ca4ccd2d49f4793099dfb5fdb",
    "d94354ac9cf3024f57409bd74eec6b4c",
    "cd92a26534dba48cd785cdcc0b3e6bd1",
    "21232f297a57a5a743894a0e4a801fc3",
    "34d121532c2b19bfd00b83997e207424",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "26db95d875347aeff76efedb23668bc3",
    "aac7e9d039d627c6c59754f8533dd660",
    "215e49351f6d8b316c9ae1c524a7c009",
    "e3afed0047b08059d0fada10f400c1e5",
    "8d7f41945be4937b7c470da070255d33",
    "357742da3f7a2fcec0fcffa840db38ce",
    "98d081653aed0e54dbf8316cb4640de7",
    "34b339799d540a72bf1c408c0e68afdd",
    "fe4a8d1cc3ae7158c3f40899c190d16a",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "63a9f0ea7bb98050796b649e85481845",
    "4297f44b13955235245b2497399d7a93",
    "70a73f40ea03aff27aed659282db31c9",
    "b5829ffb92dbda49c2d98ff00acfc098",
    "8640540da140f70c46b7bca31743b393",
    "26ff7a4427e83cdb2b0c7d1558e31427",
    "dfd828ad46e81934947c3280390742e8",
    "ac95af977423127b08385897bde275cb",
    "3ffca08260070f894dd47244c034c216",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "99974f541e529d1425304e27772be176",
    "f0eb63005912fce8c66288a633229d9f",
    "432c871b61e55bf0a074cc824e984340",
    "cf04cb0a94c2084743ef97cbf3319848",
    "c55ea333d1bce645ff9a36bb7d812ff1",
    "78fa5fe2f5f6682e415e1a1ec607ba4c",
    "f02368945726d5fc2a14eb576f7276c0",
    "712f79adead18f54eac40a84887d82f5"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_password_only_lf)
{
  std::stringstream input;
  input << "1999kpi\n"
           "adminadminadmin\n"
           "rootadmin\n"
           "admin\n"
           "LOLOLOWKA\n"
           "bananek1\n"
           "alex123x\n"
           "jek295\n"
           "arigato559669\n"
           "Admin\n"
           "usipusi123\n"
           "Mata\n"
           "lololo123\n"
           "<password>\n"
           "13rfrfle\n"
           "bananek1\n"
           "root\n"
           "123123\n"
           "craft123\n"
           "opensite\n"
           "w334455\n"
           "gfgrf123\n"
           "Lomat222\n"
           "LeoPlay123\n"
           "sasha2006\n"
           "bananek1\n"
           "danila2005\n"
           "89277800752\n"
           "iopGhJ678%\n"
           "as527752\n"
           "polozyura1\n"
           "Leonidova2003\n"
           "bonjour\n"
           "20031512\n";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{});
  const std::vector<std::string> hashes{
    "da83e82ca4ccd2d49f4793099dfb5fdb",
    "d94354ac9cf3024f57409bd74eec6b4c",
    "cd92a26534dba48cd785cdcc0b3e6bd1",
    "21232f297a57a5a743894a0e4a801fc3",
    "34d121532c2b19bfd00b83997e207424",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "26db95d875347aeff76efedb23668bc3",
    "aac7e9d039d627c6c59754f8533dd660",
    "215e49351f6d8b316c9ae1c524a7c009",
    "e3afed0047b08059d0fada10f400c1e5",
    "8d7f41945be4937b7c470da070255d33",
    "357742da3f7a2fcec0fcffa840db38ce",
    "98d081653aed0e54dbf8316cb4640de7",
    "34b339799d540a72bf1c408c0e68afdd",
    "fe4a8d1cc3ae7158c3f40899c190d16a",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "63a9f0ea7bb98050796b649e85481845",
    "4297f44b13955235245b2497399d7a93",
    "70a73f40ea03aff27aed659282db31c9",
    "b5829ffb92dbda49c2d98ff00acfc098",
    "8640540da140f70c46b7bca31743b393",
    "26ff7a4427e83cdb2b0c7d1558e31427",
    "dfd828ad46e81934947c3280390742e8",
    "ac95af977423127b08385897bde275cb",
    "3ffca08260070f894dd47244c034c216",
    "407c2f95e4bbecf9cdc3a96a6f6342f8",
    "99974f541e529d1425304e27772be176",
    "f0eb63005912fce8c66288a633229d9f",
    "432c871b61e55bf0a074cc824e984340",
    "cf04cb0a94c2084743ef97cbf3319848",
    "c55ea333d1bce645ff9a36bb7d812ff1",
    "78fa5fe2f5f6682e415e1a1ec607ba4c",
    "f02368945726d5fc2a14eb576f7276c0",
    "712f79adead18f54eac40a84887d82f5"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_and_hex)
{
  std::stringstream input;
  input << "zzzzzz@example.com:$HEX[d8b3d8aed8b3d8ae31393634]\n"
           "zzzzz@example.com:$HEX[e2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978f]\n"
           "zzzzz@example.com:$HEX[d09cd095d0a0d0a3d091d090d09dd098]\n"
           "zzzzzzz@example.com.au:$HEX[6c696e6b6564696e2122c2a3]\n"
           "zzzzzzzzzz@example.com:$HEX[5a415054c4b059414e]\n"
           "z@example.com:$HEX[737965647a616cc4b1]\n"
           "zzzzz@example.com.br:$HEX[676f6ec3a7616c766573]\n"
           "zzzzz@example.com:$HEX[d0b0d0bad0b0d0b4d0b5d0bcd0b8d0ba]\n"
           "zzzz@example.com:$HEX[737665746c6fc48dc599c5be]\n"
           "zzzzzz@example.com:$HEX[d985d8aed985d8aed985d8ae]";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{});
  std::vector<std::string> hashes{
    "c8498d5ccdbea55e7fc9ceb31137ee87",
    "a3359d7b81428a02c443e69a7c8a931d",
    "e9a024a9e452d6712198a606212728e3",
    "49eb91943b82b6943838ecd7039fe7fd",
    "c188052534e90b1181921d420fe44052",
    "e42eb9ff8e8a6740eb7b3b7b2bda509b",
    "eb594ad2b95c6444990aa737302284ce",
    "225cf62385e7513b7053db2813a772b0",
    "271873e01ea8c2d253493653e52e5a93",
    "56f9a8d20e3bb57777202d3c6616eea2"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash != gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_semicolon)
{
  std::stringstream input;
  input << "xxxxx@yahoo.com;$HEX[d8b3d8aed8b3d8ae31393634]\n"
           "xxxxx@yahoo.com;$HEX[e2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978f]\n"
           "xxxxxx@yahoo.com;$HEX[d09cd095d0a0d0a3d091d090d09dd098]\n"
           "xxxxx@yahoo.com.au;$HEX[6c696e6b6564696e2122c2a3]\n"
           "xxxxx@yahoo.com;$HEX[5a415054c4b059414e]\n"
           "xxxxx@yahoo.com;$HEX[737965647a616cc4b1]\n"
           "xxxx@yahoo.com.br;$HEX[676f6ec3a7616c766573]\n"
           "xxxxxx@yahoo.com;$HEX[d0b0d0bad0b0d0b4d0b5d0bcd0b8d0ba]\n"
           "xxxxxxxxxx@yahoo.com;$HEX[737665746c6fc48dc599c5be]\n"
           "xxxxxxxxx@yahoo.com;$HEX[d985d8aed985d8aed985d8ae]";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{pwned::UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords});
  std::vector<std::string> hashes{
    "c8498d5ccdbea55e7fc9ceb31137ee87",
    "a3359d7b81428a02c443e69a7c8a931d",
    "e9a024a9e452d6712198a606212728e3",
    "49eb91943b82b6943838ecd7039fe7fd",
    "c188052534e90b1181921d420fe44052",
    "e42eb9ff8e8a6740eb7b3b7b2bda509b",
    "eb594ad2b95c6444990aa737302284ce",
    "225cf62385e7513b7053db2813a772b0",
    "271873e01ea8c2d253493653e52e5a93",
    "56f9a8d20e3bb57777202d3c6616eea2"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_tab)
{
  std::stringstream input;
  input << "xxxxx@yahoo.com\t$HEX[d8b3d8aed8b3d8ae31393634]\n"
           "xxxxx@yahoo.com\t$HEX[e2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978f]\n"
           "xxxxxx@yahoo.com\t$HEX[d09cd095d0a0d0a3d091d090d09dd098]\n"
           "xxxxx@yahoo.com.au\t$HEX[6c696e6b6564696e2122c2a3]\n"
           "xxxxx@yahoo.com\t$HEX[5a415054c4b059414e]\n"
           "xxxxx@yahoo.com\t$HEX[737965647a616cc4b1]\n"
           "xxxx@yahoo.com.br\t$HEX[676f6ec3a7616c766573]\n"
           "xxxxxx@yahoo.com\t$HEX[d0b0d0bad0b0d0b4d0b5d0bcd0b8d0ba]\n"
           "xxxxxxxxxx@yahoo.com\t$HEX[737665746c6fc48dc599c5be]\n"
           "xxxxxxxxx@yahoo.com\t$HEX[d985d8aed985d8aed985d8ae]";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{pwned::UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords});
  std::vector<std::string> hashes{
    "c8498d5ccdbea55e7fc9ceb31137ee87",
    "a3359d7b81428a02c443e69a7c8a931d",
    "e9a024a9e452d6712198a606212728e3",
    "49eb91943b82b6943838ecd7039fe7fd",
    "c188052534e90b1181921d420fe44052",
    "e42eb9ff8e8a6740eb7b3b7b2bda509b",
    "eb594ad2b95c6444990aa737302284ce",
    "225cf62385e7513b7053db2813a772b0",
    "271873e01ea8c2d253493653e52e5a93",
    "56f9a8d20e3bb57777202d3c6616eea2"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_space)
{
  std::stringstream input;
  input << "xxxxx@yahoo.com $HEX[d8b3d8aed8b3d8ae31393634]\n"
           "xxxxx@yahoo.com $HEX[e2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978f]\n"
           "xxxxxx@yahoo.com $HEX[d09cd095d0a0d0a3d091d090d09dd098]\n"
           "xxxxx@yahoo.com.au $HEX[6c696e6b6564696e2122c2a3]\n"
           "xxxxx@yahoo.com $HEX[5a415054c4b059414e]\n"
           "xxxxx@yahoo.com $HEX[737965647a616cc4b1]\n"
           "xxxx@yahoo.com.br $HEX[676f6ec3a7616c766573]\n"
           "xxxxxx@yahoo.com $HEX[d0b0d0bad0b0d0b4d0b5d0bcd0b8d0ba]\n"
           "xxxxxxxxxx@yahoo.com $HEX[737665746c6fc48dc599c5be]\n"
           "xxxxxxxxx@yahoo.com $HEX[d985d8aed985d8aed985d8ae]";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{pwned::UserPasswordReaderOptions::forceEvaluateHexEncodedPasswords});
  std::vector<std::string> hashes{
    "c8498d5ccdbea55e7fc9ceb31137ee87",
    "a3359d7b81428a02c443e69a7c8a931d",
    "e9a024a9e452d6712198a606212728e3",
    "49eb91943b82b6943838ecd7039fe7fd",
    "c188052534e90b1181921d420fe44052",
    "e42eb9ff8e8a6740eb7b3b7b2bda509b",
    "eb594ad2b95c6444990aa737302284ce",
    "225cf62385e7513b7053db2813a772b0",
    "271873e01ea8c2d253493653e52e5a93",
    "56f9a8d20e3bb57777202d3c6616eea2"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_CASE(test_userpasswordreader_mail_and_hex_auto)
{
  std::stringstream input;
  input << "zzzzzz@example.com:$HEX[d8b3d8aed8b3d8ae31393634]\n"
           "zzzzz@example.com:$HEX[e2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978fe2978f]\n"
           "zzzzz@example.com:$HEX[d09cd095d0a0d0a3d091d090d09dd098]\n"
           "zzzzzzz@example.com.au:$HEX[6c696e6b6564696e2122c2a3]\n"
           "zzzzzzzzzz@example.com:$HEX[5a415054c4b059414e]\n"
           "z@example.com:$HEX[737965647a616cc4b1]\n"
           "zzzzz@example.com.br:$HEX[676f6ec3a7616c766573]\n"
           "zzzzz@example.com:$HEX[d0b0d0bad0b0d0b4d0b5d0bcd0b8d0ba]\n"
           "zzzz@example.com:$HEX[737665746c6fc48dc599c5be]\n"
           "zzzzzz@example.com:$HEX[d985d8aed985d8aed985d8ae]";
  pwned::UserPasswordReader reader(input, std::vector<pwned::UserPasswordReaderOptions>{pwned::UserPasswordReaderOptions::autoEvaluateHexEncodedPasswords});
  std::vector<std::string> hashes{
    "c8498d5ccdbea55e7fc9ceb31137ee87",
    "a3359d7b81428a02c443e69a7c8a931d",
    "e9a024a9e452d6712198a606212728e3",
    "49eb91943b82b6943838ecd7039fe7fd",
    "c188052534e90b1181921d420fe44052",
    "e42eb9ff8e8a6740eb7b3b7b2bda509b",
    "eb594ad2b95c6444990aa737302284ce",
    "225cf62385e7513b7053db2813a772b0",
    "271873e01ea8c2d253493653e52e5a93",
    "56f9a8d20e3bb57777202d3c6616eea2"
  };
  for (const std::string &hash : hashes)
  {
    if (reader.eof())
      break;
    const pwned::Hash &correctHash = pwned::Hash::fromHex(hash);
    const pwned::Hash &gotHash = reader.nextPasswordHash();
    BOOST_TEST(correctHash == gotHash);
  }
}

BOOST_AUTO_TEST_SUITE_END()
