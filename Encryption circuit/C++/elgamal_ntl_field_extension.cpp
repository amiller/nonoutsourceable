/*
 *
 *  Created on: May 3, 2014
 *      Author: ahmed
 */

#include <stdio.h>
#include <gmp.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pX.h>
#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZ_pEX.h>

NTL_CLIENT


using namespace NTL;

int main() {

	/***  Part I. Field Configurations ***/

		// Setting Pinocchio's field F_p
		ZZ_p::init(
				conv<ZZ>(
						"16798108731015832284940804142231733909759579603404752749028378864165570215949"));

		// Setting the extended field: F_{p^mue}
		// Defining the irreducible polynomial x^8 - 2
		ZZ_pX P;
		P.SetLength(9);
		P[0] = -2;
		P[8] = 1;

		ZZ_pE::init(P); // define F_{p^mue} as the extended field


	/*** EL GAMAL Encryption - Wikipedia Notations mostly used **/
	/***  Part II. Simulating a *simple* Key Generation ***/

		cout << "\KeyGEn\n==========================" << endl;


		//	ZZ_pE g = random_ZZ_pE();

		ZZ_pX poly;
		poly.SetLength(8);
		poly[0] = 1;
		poly[1] = 2;
		poly[2] = 3;
		poly[3] = 4;
		poly[4] = 5;
		poly[5] = 6;
		poly[6] = 7;
		poly[7] = 8;
		ZZ_pE g =  conv<ZZ_pE>(poly);

		cout << "g: " <<  g  << "/// simple one for now for experiments"<< endl;

		ZZ x = RandomBits_ZZ(1500); // random value in G
		ZZ_pE h = power(g,x); // h = g^x
		cout << "h = g^x = " <<  h << endl;

		// the public key now is mainly g and h

	/***  Part III. Simulating encryption ***/

		cout << "\nEncryption\n==========================" << endl;

		ZZ_pE message[4];

		// Generate random messages
		for(int i = 0; i < 4; i++){
			message[i] = random_ZZ_pE();
			cout << "Message Chunk: " << i << " " << message[i] << endl;
		}

		//ZZ y = RandomBits_ZZ(1500); // random value in G
		ZZ y = conv<ZZ>(25); // a testing value for now

		ZZ_pE s = power(h,y); // s = h^y
		cout << "h^y: " << s << endl;


		ZZ_pE c1 = power(g,y); // c1 = g^y
		cout << "g^y: " << c1 << endl;
		ZZ_pE c2[4];

		cout << "\n" ;
		for(int i = 0; i < 4; i++){
			c2[i] = message[i]*s;
			cout << "Encrypted Message Chunk: " << i << " " << c2[i] << endl;
		}


	/***  Part IV. Decryption ***/

		cout << "\nDecryption\n==========================" << endl;

		ZZ_pE decryptedMessage[4];

		ZZ_pE one = conv<ZZ_pE>(1);

		ZZ_pE s_inv = 1/power(c1,x); // s^-1 = [(g^y)^x]^-1;

		// recovering the message back

		for(int i = 0; i < 4; i++){
			decryptedMessage[i] = c2[i]*s_inv;
			cout << "Decrypted Message Chunk: " << i << " " << decryptedMessage[i] << endl;
		}


}


