#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#define CHUNK_SIZE 4096
#define MAGIC_LEN 4

int main(int argc, char *argv[]){
    
    if(sodium_init() < 0){fprintf(stderr, "sodium initiation failed\n");return 1;}

    int rc = 1;                    // assume failure
    int output_valid = 0;          
    FILE *file = NULL;             
    FILE *new_file = NULL;

    //################################

    
    char password[255];
    unsigned char salt[crypto_pwhash_SALTBYTES];                              // 16 bytes
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];       // 32 bytes
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES]; // 24 bytes (the Initialization Vector)
    unsigned char in_buf[CHUNK_SIZE];                                        // plaintext chunk you read
    unsigned char out_buf[CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES]; // ciphertext (bigger)
    unsigned char next_buf[CHUNK_SIZE]; 
static const unsigned char MAGIC[MAGIC_LEN] = { 'M', 'E', 'R', '1' };
    unsigned char file_magic[MAGIC_LEN];
    const char *mode, *name, *new_name;  
    char mode_buf[16], name_buf[260], new_name_buf[260];
    int encrypting;
   
    crypto_secretstream_xchacha20poly1305_state state;

    if (argc >= 4) {
    // arguments provided → point at argv
    mode     = argv[1];
    name     = argv[2];
    new_name = argv[3];
} else {
    // no arguments (double-clicked) → prompt for them
    printf("CLI usage: %s <input file name> <output file name>\n", argv[0]);
    printf("Mode (encrypt/decrypt): ");
    if (!fgets(mode_buf, sizeof mode_buf, stdin)) return 1;
    mode_buf[strcspn(mode_buf, "\n")] = '\0';
    mode = mode_buf;

     if      (strcmp(mode, "encrypt") == 0) encrypting = 1;
    else if (strcmp(mode, "decrypt") == 0) encrypting = 0;
    else { fprintf(stderr, "Mode must be 'encrypt' or 'decrypt'\n"); printf("Press enter to continue..."); getchar(); return 1;}


    printf("Input file: ");
    if (!fgets(name_buf, sizeof name_buf, stdin)) return 1;
    name_buf[strcspn(name_buf, "\n")] = '\0';
    name = name_buf;

    printf("Output file: ");
    if (!fgets(new_name_buf, sizeof new_name_buf, stdin)) return 1;
    new_name_buf[strcspn(new_name_buf, "\n")] = '\0';
    new_name = new_name_buf;
}

    //File

    file = fopen(name, "rb");
    if(file == NULL){perror("ERR_NULL_FILE"); goto cleanup;}

    // New file

    new_file = fopen(new_name, "wb");
    if(new_file == NULL){printf("Error while creating the output file\n");goto cleanup;}

    //password

    printf("Enter password(max 255 bytes): ");
    if (fgets(password, sizeof(password), stdin) == NULL) {
    fprintf(stderr, "Failed to read password\n");
    goto cleanup;
}
    password[strcspn(password, "\n")] = '\0';   // strip the trailing newline

    // salt: encrypt GENERATES it; decrypt READS it from the file
    if(encrypting){randombytes_buf(salt, sizeof(salt));
        //ENCRYPTION
    if(fread(file_magic, 1, MAGIC_LEN, file) != MAGIC_LEN){
    fprintf(stderr, "File too short\n"); 
    goto cleanup;
}
if (memcmp(file_magic, MAGIC, MAGIC_LEN) == 0) {   // == 0: already a marer file
    fprintf(stderr, "This file appears to be already encrypted. Continue anyway? (y/N): ");
    char answer[8];
    if (fgets(answer, sizeof answer, stdin) == NULL ||
        (answer[0] != 'y' && answer[0] != 'Y')) {
        fprintf(stderr, "Aborted.\n");
        goto cleanup;
    }
}

rewind(file);

    if (crypto_pwhash(key, sizeof key,
                  password, strlen(password),
                  salt,
                  crypto_pwhash_OPSLIMIT_MODERATE,
                  crypto_pwhash_MEMLIMIT_MODERATE,
                  crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Key derivation failed (out of memory?)\n");
   goto cleanup;
}
    if(fwrite(MAGIC, 1, MAGIC_LEN, new_file) != MAGIC_LEN){
        fprintf(stderr, "Failed to write the magic bytes to output\n");
        goto cleanup;
    }
   
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

    

   if (fwrite(salt, 1, sizeof salt, new_file) != sizeof salt) {
    fprintf(stderr, "Failed to write salt to output\n");
    goto cleanup;
}
    if (fwrite(header, 1, sizeof header, new_file) != sizeof header) {
    fprintf(stderr, "Failed to write header to output\n");
    goto cleanup;
    }

    
  size_t n = fread(in_buf, 1, CHUNK_SIZE, file);
if (n == 0 && ferror(file)) {
    fprintf(stderr, "Error reading input file\n");
    goto cleanup;
}

while (n > 0) {
    size_t next_n = fread(next_buf, 1, CHUNK_SIZE, file);
    if (next_n == 0 && ferror(file)) {
        fprintf(stderr, "Error reading input file\n");
       goto cleanup;
    }

    unsigned char tag = (next_n == 0)
        ? crypto_secretstream_xchacha20poly1305_TAG_FINAL
        : 0;

    unsigned long long out_len;
    if (crypto_secretstream_xchacha20poly1305_push(
            &state, out_buf, &out_len, in_buf, n, NULL, 0, tag) != 0) {
        fprintf(stderr, "Encryption failed\n");
        goto cleanup;
    }

    if (fwrite(out_buf, 1, out_len, new_file) != out_len) {
        fprintf(stderr, "Failed to write encrypted chunk\n");
    goto cleanup;
    }

    memcpy(in_buf, next_buf, next_n);
    n = next_n;
}


    //DECRYPTION
}else{

if(fread(file_magic, 1, MAGIC_LEN, file) != MAGIC_LEN){
    fprintf(stderr, "File too short\n"); 
  goto cleanup;
}
if (memcmp(file_magic, MAGIC, MAGIC_LEN) != 0) {   // != 0 means they DIFFER
    fprintf(stderr, "Not a marer file (bad signature)\n");
goto cleanup;
}

    
if(fread(salt, 1, sizeof(salt), file) != sizeof(salt)){
    fprintf(stderr, "File too short / not a valid encrypted file\n");
goto cleanup;
}
    
    
if (fread(header, 1, sizeof header, file) != sizeof header) {
    fprintf(stderr, "Failed to read header (file too short?)\n");
    goto cleanup;
}

if (crypto_pwhash(key, sizeof key, password, strlen(password), salt,
                  crypto_pwhash_OPSLIMIT_MODERATE, crypto_pwhash_MEMLIMIT_MODERATE,
                  crypto_pwhash_ALG_DEFAULT) != 0) {
    fprintf(stderr, "Key derivation failed\n");
   goto cleanup;
}

// then initialize decryption with it
if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0) {
    fprintf(stderr, "Invalid or corrupted header\n");
    goto cleanup;
}
size_t n = fread(in_buf, 1, CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES, file);
if (n == 0 && ferror(file)) {
    fprintf(stderr, "Error reading input file\n");
    goto cleanup;}
int done = 0;
while(n > 0){
    unsigned char tag;
    unsigned long long plain_len;

    if(crypto_secretstream_xchacha20poly1305_pull(&state, out_buf, &plain_len, &tag, in_buf, n, NULL, 0) !=0){
        fprintf(stderr, "Decryption failed: wrong password or corrupted file\n");
        goto cleanup;
    }

    if(fwrite(out_buf, 1, plain_len, new_file) != plain_len){
        fprintf(stderr, "Failed to write decrypted output\n");
        goto cleanup;
    }

    if(tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL){
        done = 1;
        break;
    }

    n = fread(in_buf, 1, CHUNK_SIZE + crypto_secretstream_xchacha20poly1305_ABYTES, file);
    if (n == 0 && ferror(file)) {
    fprintf(stderr, "Error reading input file\n");
    goto cleanup;
    }
}
if(!done){
    fprintf(stderr, "File is incomplete (truncated or not a valid encrypted file)\n");
    goto cleanup;}
}

output_valid = 1;
    rc = 0;

fprintf(stderr, "Delete the original file? (y/N): ");
char answer[8];
if (fgets(answer, sizeof answer, stdin) != NULL &&
    (answer[0] == 'y' || answer[0] == 'Y')) {
    fclose(file);      
    file = NULL;       
    if (remove(name) == 0) {
        printf("Original file deleted.\n");
    } else {
        perror("Failed to delete original");
    }
}

cleanup:
    if (file)     fclose(file);
    if (new_file) {
        fclose(new_file);
        if (!output_valid){ remove(new_name);}   // delete empty/partial output on ANY failure
    }
    printf("Press enter to continue...");
    getchar();
    return rc;
}

