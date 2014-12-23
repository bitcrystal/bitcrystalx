// Copyright (c) 2009-2012 Bitcoin Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h" // for pwalletMain
#include "bitcoinrpc.h"
#include "ui_interface.h"
#include "base58.h"
#include <fstream>

#include <boost/lexical_cast.hpp>

#define printf OutputDebugStringF

using namespace json_spirit;
using namespace std;

class CTxDump
{
public:
    CBlockIndex *pindex;
    int64 nValue;
    bool fSpent;
    CWalletTx* ptx;
    int nOut;
    CTxDump(CWalletTx* ptx = NULL, int nOut = -1)
    {
        pindex = NULL;
        nValue = 0;
        fSpent = false;
        this->ptx = ptx;
        this->nOut = nOut;
    }
};

Value importprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "importprivkey <bitcrystalprivkey> [label] [rescan=true]\n"
            "Adds a private key (as returned by dumpprivkey) to your wallet.");

    string strSecret = params[0].get_str();
    string strLabel = "";
    if (params.size() > 1)
        strLabel = params[1].get_str();

    // Whether to perform rescan after import
    bool fRescan = true;
    if (params.size() > 2)
        fRescan = params[2].get_bool();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strSecret);

    if (!fGood) throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");

    CKey key;
    bool fCompressed;
    CSecret secret = vchSecret.GetSecret(fCompressed);
    key.SetSecret(secret, fCompressed);
    CKeyID vchAddress = key.GetPubKey().GetID();
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        pwalletMain->MarkDirty();
        pwalletMain->SetAddressBookName(vchAddress, strLabel);

        if (!pwalletMain->AddKey(key))
            throw JSONRPCError(RPC_WALLET_ERROR, "Error adding key to wallet");
	
        if (fRescan) {
            pwalletMain->ScanForWalletTransactions(pindexGenesisBlock, true);
            pwalletMain->ReacceptWalletTransactions();
        }
    }

    return Value::null;
}

Value dumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "dumpprivkey <bitcrystaladdress>\n"
            "Reveals the private key corresponding to <bitcrystaladdress>.");

    string strAddress = params[0].get_str();
    CBitcoinAddress address;
    if (!address.SetString(strAddress))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid BitCrystal address");
    CKeyID keyID;
    if (!address.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to a key");
    CSecret vchSecret;
    bool fCompressed;
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    return CBitcoinSecret(vchSecret, fCompressed).ToString();
}

Value myimportprivkey(const Array& params, bool fHelp)
{
	if (fHelp || params.size() != 2)
        throw runtime_error(
            "myimportprivkey <bitcrystaladdress>\n"
            "Reveals the private key corresponding to <bitcrystaladdress>.");

	CBitcoinSecret cBitcoinSecret;
	
	string file = params[0].get_str();
	string password = params[1].get_str();
	
	ifstream file2(file, ios::in | ios::binary);
	
    if(!file2.is_open()){
        throw JSONRPCError(RPC_WALLET_ERROR, "File must be close!");
        return 0;
    }


    while(!file2.eof()){
        file2.read((char *)&cBitcoinSecret, sizeof(cBitcoinSecret));
    }
}
Value mydumpprivkey(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "mydumpprivkey <bitcrystaladdress>\n"
            "Reveals the private key corresponding to <bitcrystaladdress>.");

      if (!pwalletMain->IsLocked())
        pwalletMain->TopUpKeyPool();
	string file = params[0].get_str();
	string password = params[1].get_str();
    // Generate a new key that is added to wallet
    CPubKey newKey;
    if (!pwalletMain->GetKeyFromPool(newKey, false))
        throw JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT, "Error: Keypool ran out, please call keypoolrefill first");
    CKeyID keyID = newKey.GetID();
	CBitcoinAddress address(keyID);
    CSecret vchSecret;
    bool fCompressed;
	string strAdress = "Unknown";
    if (!pwalletMain->GetSecret(keyID, vchSecret, fCompressed))
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
    CBitcoinSecret cBitcoinSecret(vchSecret, fCompressed);
	vector<unsigned char> myPassword;
	string addr=address.ToString();
	int lengthAddr = addr.size();
	int lengthPassword = password.size();
	if (lengthPassword<lengthAddr)
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + strAddress + " is not known");
	int length = 0;
	char * pass = password.c_str();
	char * addre = addr.c_str();
	for(i = 0; i < lengthPassword; i++)
	{
		if(i<lengthAddr)
			myPassword.push_back((unsigned char)&pass[i] ^ (unsigned char)&addre[i]);
			myPassword.push_back((unsigned char)&pass[i] & (unsigned char)&addre[i]);
			myPassword.push_back((unsigned char)&pass[i] | (unsigned char)&addre[i]);
		else
			myPassword.push_back((unsigned char)&pass[i]);
	}
	uint160 myPasswordHash = Hash160(myPassword);
	int myPasswordHashLength = sizeof(myPasswordHash);
	vector<unsigned char> myVec;
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char)&myPasswordHashLength[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < myPasswordHashLength; i++)
	{
		myVec.push_back((unsigned char)myPasswordHash[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	length = sizeof(cBitcoinSecret);
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char)&length[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < length; i++)
	{
		if(i < myPasswordHashLength)
		{
			myVec.push_back((unsigned char*)&cBitcoinSecret[i] ^ (unsigned char*)&myPasswordHash[i]);
		} else {
			myVec.push_back((unsigned char*)&cBitcoinSecret[i]);
		}
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	uint160 hash = Hash160(myVec);
	int hashLength = sizeof(hash);
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char*)&hashLength[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < hashLength; i++)
	{
		myVec.push_back((unsigned char*)&hash[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	length = sizeof(address);
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char*)&length[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < length; i++)
	{
		if(i < myPasswordHashLength)
			myVec.push_back((unsigned char*)&address[i] ^ (unsigned char*)&myPasswordHash[i]);
		else
			myVec.push_back((unsigned char*)&address[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	uint160 hash = Hash160(myVec);
	hashLength = sizeof(hash);
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char*)&hashLength[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < hashLength; i++)
	{
		myVec.push_back((unsigned char*)&hash[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	string ve(myVec.begin(), myVec.end());
	Array newParams;
	newParams.push_back(addr);
	newParams.push_back(ve);
	string ret = (string)signmessage(newParams, false);
	length = ret.size();
	char * rete = ret.c_str();
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char*)&length[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	for(int i = 0; i < length; i++)
	{
		myVec.push_back((unsigned char*)&rete[i]);
	}
	for(int i = 0; i < 1; i++)
	{
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
		myVec.push_back((unsigned char)1);
		myVec.push_back((unsigned char)2);
		myVec.push_back((unsigned char)3);
		myVec.push_back((unsigned char)4);
		myVec.push_back((unsigned char)10);
		myVec.push_back((unsigned char)13);
	}
	hashLength=sizeof(myVec)+sizeof(int);
	for(int i = 0; i < sizeof(int); i++)
	{
		myVec.push_back((unsigned char*)&hashLength[i]);
	}
	ofstream file2(file, ios::out | ios::app | ios::binary);

    if(!file2.is_open()){
        throw JSONRPCError(RPC_WALLET_ERROR, "File must be close!");
    } else {
        file2.write((char*)&myVec, sizeof(myVec));
        file2.close();
    }
	return address.ToString();
}
