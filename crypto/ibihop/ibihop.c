/***
  This source code implements the IBIHOP protocol and provide a demonstration of its use.

  To Compile
	1. Install OpenSSL development libraries.
		sudo apt-get install libssl-dev
	2. Compile IBIHOP source code
		gcc ibihop.c -o ibihop –lcrypto
***/
#include <openssl/bn.h>
#include <openssl/ec.h>
//#include <openssl/pem.h>


#define ECCURVE	"secp521r1"

// structure of parameters of prover (tag)
typedef struct para_pvr {
  BIGNUM *r;
  BIGNUM *order;
  const BIGNUM *sk;
  BIGNUM *s;
  const EC_POINT *vpk;	// verifier's public key
  EC_POINT *R;
  const EC_KEY *key;
  const EC_GROUP *group;
} PARA_PRO;

// structure of parameters of verifier (reader)
typedef struct para_ver {
  BIGNUM *e;
  BIGNUM *e_inv;
  BIGNUM *order;
  BIGNUM *f;
  const BIGNUM *sk;
  const EC_POINT *ppk;	// prover's public key
  EC_POINT *E;
  const EC_KEY *key;
  const EC_GROUP *group;
} PARA_VER;

/*
void* initialize()
{
  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
}
*/

/***
  This function generates a pair of public and private keys.
  
  Input:
  	*curve - name of the ellipic curve.
  	
  Return:
	EC_KEY *key - a random public and private key.
	NULL - key generation failed.
***/
EC_KEY* keygen(char *curve)
{
  EC_KEY *key = NULL;
  int eccgrp;
  eccgrp = OBJ_txt2nid(curve);
  key = EC_KEY_new_by_curve_name(eccgrp);

  if (!(EC_KEY_generate_key(key)))
    return NULL;

  return key;
}

/***
  This function generates a challenge for prover. The output is supposed to be used in Message 1 of IBIHOP.
  
  Input:
  	*params - structure (pointer) of verifier's system parameters.

  Return:
	0 - the challenge message is generated successfully.
	1 - EC group information is not given (NULL).
	2 - message generation failed.
***/
int challenge_prover(PARA_VER *params)
{
  if (params->group != NULL)
    params->E = EC_POINT_new(params->group);
  else
    return 1;
  EC_GROUP_get_order(params->group, params->order, NULL);
  BN_rand_range(params->e, params->order);

  BN_CTX *ctx = BN_CTX_new();
  BN_mod_inverse(params->e_inv, params->e, params->order, ctx);

  // calculate E = e_invP
  if (!EC_POINT_mul(params->group, params->E, params->e_inv, NULL, NULL, ctx))
    return 2;

  BN_CTX_free(ctx);
  
  return 0;
}

/***
  This function generates a challenge for verifier. The output is supposed to be used in Message 2 of IBIHOP.
  
  Input:
  	*params - structure (pointer) of prover's system parameters.

  Return:
	0 - the challenge message is generated successfully.
	1 - EC group information is not given (NULL).
	2 - message generation failed.
***/
int challenge_verifier(PARA_PRO *params)
{
  if (params->group != NULL)
    params->R = EC_POINT_new(params->group);
  else
    return 1;
  EC_GROUP_get_order(params->group, params->order, NULL);
  BN_rand_range(params->r, params->order);

  BN_CTX *ctx = BN_CTX_new();
  
  if (!EC_POINT_mul(params->group, params->R, params->r, NULL, NULL, ctx))
    return 2;
    
  BN_CTX_free(ctx);
  
  return 0;
}

/***
  This function generates a response to verifier's challenge. The output is supposed to be used in Message 3 of IBIHOP.
  
  Input:
  	params	- structure (pointer) of verifier's system parameters.
  	R	- EC_POINT object pointer.	

  Return:
	0 - the challenge message is generated successfully.
	1 - EC group information is not given (NULL).
***/
int respond_prover(PARA_VER *params, EC_POINT *R)
{
  if (params->group == NULL)
    return 1;
    
  BIGNUM *tmp = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();    
  EC_POINT *ret = EC_POINT_new(params->group);
  EC_POINT *yR = EC_POINT_new(params->group);
  BN_CTX *ctx = BN_CTX_new();
  
  // calculate [yR]_x
  EC_POINT_mul(params->group, yR, NULL, R, params->sk, ctx);	
  EC_POINT_get_affine_coordinates_GFp(params->group, yR, x, y, ctx);
  
  // calculate [([yR]_x)P]_x
  EC_POINT_mul(params->group, ret, x, NULL, NULL, ctx);
  EC_POINT_get_affine_coordinates_GFp(params->group, ret, x, y, ctx);
  BN_mod_add(params->f, x, params->e, params->order, ctx);
  
  BN_free(tmp);
  BN_free(x);
  BN_free(y);
  BN_CTX_free(ctx);
  EC_POINT_free(ret);
  EC_POINT_free(yR);
  
  return 0;
}

/***
  This function generates a response to prover's challenge. The output is supposed to be used in Message 4 of IBIHOP.
  
  Input:
  	params	- structure (pointer) of prover's system parameters.
  	E	- EC_POINT object pointer.
  	f	- BIGNUM object pointer.	

  Return:
	0 - the response message is generated successfully.
	1 - EC group information is not given (NULL).
	2 - verification of verifier's response failed.
***/
int respond_verifier(PARA_PRO *params, EC_POINT *E, BIGNUM *f)
{
  if (params->group == NULL)
    return 1;
    
  BIGNUM *tmp = BN_new();
  BIGNUM *x = BN_new();
  BIGNUM *y = BN_new();
  BIGNUM *e_prime = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *ret = EC_POINT_new(params->group);
  const EC_POINT *generator = EC_POINT_new(params->group);
  EC_POINT *rY = EC_POINT_new(params->group);

  // calculate [rY]_x
  EC_POINT_mul(params->group, rY, NULL, params->vpk, params->r, ctx);
  EC_POINT_get_affine_coordinates_GFp(params->group, rY, x, y, ctx);
  
  // calculate [([rY]_x)P]_x
  EC_POINT_mul(params->group, ret, x, NULL, NULL, ctx);
  EC_POINT_get_affine_coordinates_GFp(params->group, ret, x, y, ctx);
  
  BN_mod_sub(e_prime, f, x, params->order, ctx);

  EC_POINT_mul(params->group, ret, NULL, E, e_prime, ctx);
  generator = EC_GROUP_get0_generator(params->group);
  if (EC_POINT_cmp(params->group, ret, generator, ctx) != 0)
    return 2;	// verification failed.
    
  BN_mod_mul(tmp, e_prime, params->sk, params->order, ctx);
  BN_mod_add(params->s, tmp, params->r, params->order, ctx); 
  
  BN_free(tmp);
  BN_free(x);
  BN_free(y);
  BN_free(e_prime);
  BN_CTX_free(ctx);
  EC_POINT_free(ret);
  //EC_POINT_free(generator);
  EC_POINT_free(rY);
  
  return 0;
}

/***
  This function checks the validity of prover and return 0 if the prover is valid.
  
  Input:
  	params	- structure (pointer) of verifier's system parameters.
  	R	- EC_POINT object pointer.
  	s	- BIGNUM object pointer.	

  Return:
	0 - prover is verified.
	1 - EC group information is not given (NULL).
	2 - prover verification failed.
***/
int check_validity(PARA_VER *params, EC_POINT *R, BIGNUM *s)
{
  if (params->group == NULL)
    return 1;
    
  EC_POINT *sP = EC_POINT_new(params->group);
  EC_POINT *negR = EC_POINT_new(params->group);
  EC_POINT *ret = EC_POINT_new(params->group);
  EC_POINT *X = EC_POINT_new(params->group);
  BN_CTX *ctx = BN_CTX_new();
  
  EC_POINT_mul(params->group, sP, s, NULL, NULL, ctx);
  EC_POINT_copy(negR, R);
  EC_POINT_invert(params->group, negR, ctx);
  EC_POINT_add(params->group, ret, sP, negR, ctx);

  EC_POINT_mul(params->group, X, NULL, ret, params->e_inv, ctx);
  if (EC_POINT_cmp(params->group, X, params->ppk, ctx) != 0)
    return 2;	// verification failed.
    
  EC_POINT_free(sP);
  EC_POINT_free(negR);
  EC_POINT_free(ret);
  EC_POINT_free(X);
  BN_CTX_free(ctx);
  
  return 0; 
}

/***
  This function initialize the structure pointer of PARA_VER.
  
  Input:
  	params	- structure pointer of PARA_VER.
***/
void PARA_VER_init(PARA_VER *params)
{
  params->e = BN_new();
  params->e_inv = BN_new();
  params->order = BN_new();
  params->f = BN_new();
  params->sk = BN_new();
  params->ppk = NULL;
  params->E = NULL;
  params->key = NULL;
  params->group = NULL;
}

/***
  This function free created objects of the structure pointer of PARA_VER.
  
  Input:
  	params	- structure pointer of PARA_VER.
***/
void PARA_VER_free(PARA_VER *params)
{
  //todo...add decision to check if object needs to free.
  BN_free(params->e);
  BN_free(params->e_inv);
  BN_free(params->order);
  BN_free(params->f);
}

/***
  This function initialize the structure pointer of PARA_PRO.
  
  Input:
  	params	- structure pointer of PARA_PRO.
***/
int PARA_PRO_init(PARA_PRO *params)
{
  params->r = BN_new();
  params->s = BN_new();
  params->order = BN_new();
  params->sk = BN_new();
  params->vpk = NULL;	// verifier's public key
  params->R = NULL;
  params->key = NULL;
  params->group = NULL;
}

/***
  This function free created objects of the structure pointer of PARA_PRO.
  
  Input:
  	params	- structure pointer of PARA_PRO.
***/
void PARA_PRO_free(PARA_PRO *params)
{
  //todo...add decision to check if object needs to free.
  BN_free(params->r);
  BN_free(params->order);
  //BN_free(params->sk);
  BN_free(params->s);
}

/***
  This is a demonstration for the usage of IBIHOP funcitons.
***/
int main()
{
  //initialize();
  // initialize structures of parameters for verifier (reader) and prover (tag).
  printf("Initializing system parameters of prover and verifier...\n");
  PARA_VER *params_a;
  PARA_PRO *params_b;
  params_a = (PARA_VER*) malloc(sizeof(PARA_VER));
  PARA_VER_init(params_a);
  params_b = (PARA_PRO*) malloc(sizeof(PARA_PRO));
  PARA_PRO_init(params_b);

  // generate public and private key pairs.
  printf("Generating keys of prover and verifier...\n");
  params_a->key = keygen(ECCURVE);
  params_b->key = keygen(ECCURVE);
  
  // set keys to verifier and prover.
  printf("Setting keys to prover and verifier...\n");
  params_a->sk = EC_KEY_get0_private_key(params_a->key);
  params_a->ppk = EC_KEY_get0_public_key(params_b->key);	// set prover's public key to verifier.
  params_b->sk = EC_KEY_get0_private_key(params_b->key);
  params_b->vpk = EC_KEY_get0_public_key(params_a->key);	// set verifier's public key to prover.

  printf("Setting other system parameters...\n");
  params_a->group = EC_KEY_get0_group(params_a->key);	// set EC group information.
  params_b->group = EC_KEY_get0_group(params_b->key);	// set EC group information.

  EC_GROUP_get_order(params_a->group, params_a->order, NULL);	// set order of group
  EC_GROUP_get_order(params_b->group, params_b->order, NULL);	// set order of group
 
  printf("Message flow 1: Verifier challenges prover by sending a point E...\n");
  challenge_prover(params_a);	
  
  printf("Message flow 2: Prover challenges verifier by sending a piont R...\n");
  challenge_verifier(params_b);
  
  printf("Message flow 3: Verifier responds prover's challenge by sending an integer f...\n");
  respond_prover(params_a, params_b->R);
  
  printf("Message flow 4: Prover responds verifier's challenge by sending an integer s...\n");
  if (respond_verifier(params_b, params_a->E, params_a->f) != 0)
    printf("Verifier is invalid.\n");
  else
    printf("Verifier is valid.\n");
  
  printf("Verifier checks validity of prover's response...\n");
  if (check_validity(params_a, params_b->R, params_b->s) != 0)
    printf("Prover is invalid.\n");
  else
    printf("Prover is valid.\nMutual authentication succeed.\n");
  
  printf("Freeing parameters...\n");
  PARA_VER_free(params_a);
  PARA_PRO_free(params_b);
  printf("end of program.\n");

  return 0;
}

