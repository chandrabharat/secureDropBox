package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username         string
	Password         string
	Secretkey        userlib.PKEDecKey
	SignKey          userlib.DSSignKey
	FN_to_numRevokes map[string][]byte
	FN_to_suffix     map[string][]byte
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Content []byte
	Length  int
	MM_MD   map[userlib.UUID][][]byte
}

type Invite struct {
	MM_ek []byte
	MM_mk []byte
	MM_id userlib.UUID
}

type MiddleMan struct {
	File_encr_k []byte
	File_mac_k  []byte
	Suffix      []byte
	Users       map[string]userlib.UUID
}

// NOTE: The following methods have toy (insecure!) implementations.

// Returns the encryption_key and mac_key derived from the root_k with string str as hash_kdf string argument
func (userdata *User) encryptAndMacUserObj() (err error) {
	// This is the PBKDF function PBKDF(pass, user, 16)
	var root_k = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)
	encr_k, err_encr := userlib.HashKDF(root_k, []byte("user encryption"))

	// If encryption unsuccessful return
	if err_encr != nil {
		return err_encr
	}

	mac_k, err_mac := userlib.HashKDF(root_k, []byte("user mac"))

	// If mac unsuccessful return
	if err_mac != nil {
		return err_mac
	}

	encr_k, mac_k = last16Bytes(encr_k), last16Bytes(mac_k)

	userdata_byte_arr, err := json.Marshal(userdata)

	if err != nil {
		return err
	}

	// Encrypt the user object
	var e1 = userlib.SymEnc(encr_k, userlib.RandomBytes(16), userdata_byte_arr)

	e1_byte_arr, err := json.Marshal(e1)

	// Mac the encryption of the user object
	mac1, err := userlib.HMACEval(mac_k, e1_byte_arr)

	e1_and_mac1 := map[string][]byte{"encryption": e1, "mac": mac1}

	e1_and_mac1_arr, err := json.Marshal(e1_and_mac1)

	//

	last_16 := last16Bytes(userlib.Hash([]byte(userdata.Username)))
	user_uuid, err := uuid.FromBytes(last_16)

	// Store <UUID(H(user)), e1 || mac1>
	userlib.DatastoreSet(user_uuid, e1_and_mac1_arr)

	return nil
}

func last16Bytes(byte_arr []byte) (ret_arr []byte) {
	var last_16 = byte_arr[len(byte_arr)-16:]
	return last_16
}

// Return true if string is empty or UUID(H(username)) is already in datastore
func InitUserErrorCheck(username string) (hasError bool) {

	if len(username) == 0 {
		return true
	}

	var username_arr = []byte(username)

	// UUID takes in 16 bytes so slice hash s.t. you use the last 16 bytes
	last_16 := last16Bytes(userlib.Hash(username_arr))
	user_key, err := uuid.FromBytes(last_16)

	// Edge case if UUID function fails
	if err != nil {
		fmt.Println(err)
		return true
	}

	_, inDataStore := userlib.DatastoreGet(user_key)
	if inDataStore {
		return true
	}

	return false
}

func checkError(err error, message string) (err2 error, hasErr bool) {
	if err != nil {
		return errors.New(message), true
	} else {
		return nil, false
	}
}

func InitUser(username string, password string) (userdataptr *User, err error) {
	if InitUserErrorCheck(username) {
		return nil, errors.New("Username is not valid")
	}

	// UUID = UUID(H(username + RSA Key))
	var username_arr = []byte(username)

	var rsa_key = []byte("RSA Key")
	var ds_key = []byte("Signature key")
	var final_str = append(username_arr, rsa_key...)

	last_16 := last16Bytes(userlib.Hash(final_str))

	err2, hasErr := checkError(err, "FromBytes failed")

	if hasErr {
		return nil, err2
	}

	// Create public_k and private_k RSA keys
	PKEEncKey, PKEDecKey, err := userlib.PKEKeyGen()

	err2, hasErr = checkError(err, "PKEKeyGen failed")

	if hasErr {
		return nil, err2
	}

	// Store UUID(H(Username + RSA Key)[16 bytes], public_k) in keystore
	myString := string(last_16[:])
	err = userlib.KeystoreSet(myString, PKEEncKey)

	err2, hasErr = checkError(err, "Keystore set failed")

	if hasErr {
		return nil, err2
	}

	// Compute UUID(H(username + Signature key))
	final_str = append(username_arr, ds_key...)
	last_16 = last16Bytes(userlib.Hash(final_str))

	// Create public_k and private_k keys
	DSSignKey, DSVerifyKey, err := userlib.DSKeyGen()

	err2, hasErr = checkError(err, "DSKeyGen failed")

	if hasErr {
		return nil, err2
	}

	// Store UUID(H(Username + Signature key)[16 bytes], DSVerifyKey) in keystore
	myString = string(last_16[:])
	err = userlib.KeystoreSet(myString, DSVerifyKey)

	err2, hasErr = checkError(err, "Keystore set failed")

	if hasErr {
		return nil, err2
	}

	// Create the user object
	var userdata User
	userdata.Username = username
	userdata.Password = password
	// Store private_k as attribute of User
	userdata.Secretkey = PKEDecKey
	userdata.SignKey = DSSignKey

	userdata.FN_to_numRevokes = make(map[string][]byte)
	userdata.FN_to_suffix = make(map[string][]byte)

	err = userdata.encryptAndMacUserObj()

	if err != nil {
		return nil, err
	}

	return &userdata, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {

	// Compute the UUID of the username UUID(H(username))
	var username_arr = []byte(username)
	last_16 := last16Bytes(userlib.Hash(username_arr))
	user_key, err := uuid.FromBytes(last_16)

	// See if UUID errors out
	err2, hasErr := checkError(err, "UUID fromBytes username lookup error")

	if hasErr {
		return nil, err2
	}

	// Retrieve <UUID(H(user)), e1 || mac1>
	e1_and_mac1_arr, inDataStore := userlib.DatastoreGet(user_key)

	// Error check if it is not in the dataStore
	if inDataStore == false {
		return nil, errors.New("The username is not in datastore")
	}

	// Unmarshal to get the encryption and mac objects
	e1_and_mac1 := make(map[string][]byte)

	err = json.Unmarshal(e1_and_mac1_arr, &e1_and_mac1)

	err2, hasErr = checkError(err, "Encryption and Mac unmarshall error")

	if hasErr {
		return nil, err2
	}

	encrypt_obj := e1_and_mac1["encryption"]
	mac_obj := e1_and_mac1["mac"]

	// Generate User object corresponding to username and password
	// This is the PBKDF function PBKDF(pass, user, 16)
	root_k := userlib.Argon2Key([]byte(password), []byte(username), 16)
	encr_k, err_encr := userlib.HashKDF(root_k, []byte("user encryption"))

	// If encryption unsuccessful return
	if err_encr != nil {
		return nil, err_encr
	}

	mac_k, err_mac := userlib.HashKDF(root_k, []byte("user mac"))

	// If mac unsuccessful return
	if err_mac != nil {
		return nil, err_mac
	}

	encr_k, mac_k = last16Bytes(encr_k), last16Bytes(mac_k)

	encrypt_byte_arr, err := json.Marshal(encrypt_obj)

	err2, hasErr = checkError(err, "Converting the encrypted user object into"+
		"a byte array was unsuccessful")

	if hasErr {
		return nil, err2
	}

	compare_mac_obj, err := userlib.HMACEval(mac_k, encrypt_byte_arr)

	err2, hasErr = checkError(err, "HMACEval error")

	if hasErr {
		return nil, err2
	}

	if !userlib.HMACEqual(compare_mac_obj, mac_obj) {
		return nil, errors.New("HMACEqual error")
	}

	// Mac and encryption keys match; check to see if username/password match
	// and if they do then return the object

	userdata := userlib.SymDec(encr_k, encrypt_obj)

	var userdata_obj User
	err = json.Unmarshal(userdata, &userdata_obj)

	err2, hasErr = checkError(err, "Unmarshall error")

	if hasErr {
		return nil, err2
	}

	if userdata_obj.Username != username || userdata_obj.Password != password {
		return nil, errors.New("The user object decryption was unsuccessful")
	}

	return &userdata_obj, nil
}

// Function returns the file_suffix, encrypted_obj, mac_obj, file_encr_k, file_mac_k assuming that user owns fileName
func (userdata *User) ownerFileMD(filename string) (suffix []byte, file_encr_k []byte, file_mac_k []byte, res_err error) {
	// Only owner has access to fn_to_suffix
	var fn_suffix = userdata.FN_to_suffix[filename]

	if fn_suffix == nil {
		return nil, nil, nil, errors.New("Cannot retrieve file this way user is not owner")
	}

	// Compute value of H(fn_suffix + current file node)
	var curr_node, err = json.Marshal(1)

	if err != nil {
		return nil, nil, nil, err
	}

	full_str := append(fn_suffix, curr_node...)
	var hash_val = userlib.Hash(full_str)

	// Compute UUID of H(fn_suffix + current file node)
	last_16 := last16Bytes(hash_val)
	my_uuid, err := uuid.FromBytes(last_16)

	err2, hasErr := checkError(err, "UUID FromBytes error")

	if hasErr {
		return nil, nil, nil, err2
	}

	// Get the e1/mac(e1) of file from DataStore
	dataJSON, ok := userlib.DatastoreGet(my_uuid)
	if !ok {
		return nil, nil, nil, errors.New("Unable to retrieve encryption || mac of file_object given this UUID")
	}

	// Make sure that the dataJSON is valid
	if dataJSON != nil {
		// Pull out encryption object and mac object
		e1_and_mac1 := make(map[string][]byte)

		err = json.Unmarshal(dataJSON, &e1_and_mac1)

		err2, hasErr = checkError(err, "Encryption and Mac unmarshall error for file object")

		if hasErr {
			return nil, nil, nil, err2
		}

		// Get encryption and mac object
		encrypt_obj := e1_and_mac1["encryption"]
		saved_mac_obj := e1_and_mac1["mac"]

		// Get encryption and mac keys
		encr_k, mac_k, err := userdata.ownerFileKeys(filename)

		if err != nil {
			return nil, nil, nil, err
		}

		// Compute mac on encryption object
		computed_mac, err := userlib.HMACEval(mac_k, encrypt_obj)

		if err != nil {
			return nil, nil, nil, err
		}

		// Compare the saved hmac to the computed hmac to verify the encrypted file object is not tampered with
		if !userlib.HMACEqual(computed_mac, saved_mac_obj) {
			return nil, nil, nil, errors.New("HMACEqual failed for encrypted file object")
		}

		return fn_suffix, encr_k, mac_k, nil
	}
	return nil, nil, nil, errors.New("DataJSON invalid")
}

func (userdata *User) inviteToFileMD(filename string, dataJSON []byte) (file_suffix []byte, file_encr_k []byte, file_mac_k []byte, res_err error) {

	if dataJSON != nil {
		// Retrieve the middle man object from the invite object
		my_middle_man, err := userdata.inviteToMM(dataJSON)

		if err != nil {
			return nil, nil, nil, err
		}

		// Get file object

		// First find the UUID -> UUID(H(fn_suffix + "1"))
		var file_suffix = my_middle_man.Suffix
		var file_node_num = []byte("1")

		var uuid_str = append(file_suffix, file_node_num...)
		file_uuid, err := uuid.FromBytes(last16Bytes(userlib.Hash(uuid_str)))

		if err != nil {
			return nil, nil, nil, err
		}

		dataJSON, ok := userlib.DatastoreGet(file_uuid)

		if !ok {
			return nil, nil, nil, errors.New("Error with datastore get for file object")
		}

		var e1_and_mac1 = make(map[string][]byte)

		err = json.Unmarshal(dataJSON, &e1_and_mac1)

		if err != nil {
			return nil, nil, nil, err
		}

		// Get encryption and mac object for file object
		file_encrypt_obj := e1_and_mac1["encryption"]
		saved_mac_obj := e1_and_mac1["mac"]

		computed_mac_obj, err := userlib.HMACEval(my_middle_man.File_mac_k, file_encrypt_obj)

		if err != nil {
			return nil, nil, nil, err
		}

		// Verify that mac is valid for file object
		if !userlib.HMACEqual(saved_mac_obj, computed_mac_obj) {
			return nil, nil, nil, errors.New("Mac of file invalid")
		}

		return file_suffix, my_middle_man.File_encr_k, my_middle_man.File_mac_k, nil
	}
	return nil, nil, nil, errors.New("DATAjson was nil")
}

func (userdata *User) defaultStoreFile(filename string, content []byte) (err error) {

	num_revokes := userlib.RandomBytes(16)
	fn_suffix := userlib.RandomBytes(16)

	userdata.FN_to_numRevokes[filename] = num_revokes
	userdata.FN_to_suffix[filename] = fn_suffix

	var file File
	file.Content = content
	file.Length = 1
	file.MM_MD = make(map[userlib.UUID][][]byte)

	var root_k = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Compute hashKDF keys to verify encryption/mac
	var encrypt_add = []byte("encryption key")
	var mac_add = []byte("mac key")
	var curr_username = []byte(userdata.Username)

	full_hashkdf := append([]byte(filename), curr_username...)
	full_hashkdf = append(full_hashkdf, encrypt_add...)
	full_hashkdf = append(full_hashkdf, num_revokes...)
	// File encrpytion key = HashKDF(root_k, filename + username + encryption key + num_revokes)
	encr_k, err := userlib.HashKDF(root_k, full_hashkdf)
	encr_k = last16Bytes(encr_k)

	err2, hasErr := checkError(err, "HashKDF failed for encryption")

	if hasErr {
		return err2
	}

	full_hashkdf = append([]byte(filename), curr_username...)
	full_hashkdf = append(full_hashkdf, mac_add...)
	full_hashkdf = append(full_hashkdf, num_revokes...)
	// File encrpytion key = HashKDF(root_k, filename + username + mac key + num_revokes)
	mac_k, err := userlib.HashKDF(root_k, full_hashkdf)
	mac_k = last16Bytes(mac_k)

	err2, hasErr = checkError(err, "HashKDF failed for mac")

	if hasErr {
		return err2
	}

	err = userdata.encryptAndMacNode(file, encr_k, mac_k, fn_suffix, 1)

	if err != nil {
		return err
	}

	userdata.encryptAndMacUserObj()
	return nil
}

func (userdata *User) userHasInvite(filename string) (encrypt_and_sig []byte, contains_invite bool, err error) {
	var invite_str = []byte("invite")
	var filename_arr = []byte(filename)
	var curr_username = []byte(userdata.Username)

	full_str := append(filename_arr, curr_username...)
	full_str = append(full_str, invite_str...)
	var hash_val = userlib.Hash(full_str)

	// Compute UUID of H(filename + username + "invite")
	last_16 := last16Bytes(hash_val)
	my_uuid, err := uuid.FromBytes(last_16)

	err2, hasErr := checkError(err, "UUID FromBytes error")

	if hasErr {
		return nil, false, err2
	}

	encrypt_and_sig, ok := userlib.DatastoreGet(my_uuid)
	if ok {
		return encrypt_and_sig, true, nil
	} else {
		return nil, false, nil
	}
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {

	userdata, err = GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return err
	}

	// Only owner has fileName in fn_to_suffix
	var fn_suffix = userdata.FN_to_suffix[filename]
	var file_encr_k []byte
	var file_mac_k []byte

	if fn_suffix != nil {
		fn_suffix, file_encr_k, file_mac_k, err = userdata.ownerFileMD(filename)
		if err != nil {
			return err
		}
	} else {
		dataJson, ok, err := userdata.userHasInvite(filename)

		if err != nil {
			return err
		}

		if ok {
			// Case where user is not the owner and has been invited to the file
			fn_suffix, file_encr_k, file_mac_k, err = userdata.inviteToFileMD(filename, dataJson)
			if err != nil {
				return err
			}
		} else {
			// Case where file does not exist yet at all
			err := userdata.defaultStoreFile(filename, content)
			if err != nil {
				return err
			}
			return nil
		}
	}

	firstFile, err := userdata.decryptNode(fn_suffix, 1, file_encr_k, file_mac_k)

	firstFile.Content = content
	firstFile.Length = 1

	err = userdata.encryptAndMacNode(firstFile, file_encr_k, file_mac_k, fn_suffix, 1)

	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	var err error

	userdata, err = GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return err
	}

	// Only owner has fileName in fn_to_suffix
	var fn_suffix = userdata.FN_to_suffix[filename]
	var file_encr_k []byte
	var file_mac_k []byte

	if fn_suffix != nil {
		fn_suffix, file_encr_k, file_mac_k, err = userdata.ownerFileMD(filename)
		if err != nil {
			return err
		}
	} else {
		dataJson, ok, err := userdata.userHasInvite(filename)

		if err != nil {
			return err
		}

		if !ok {
			return errors.New("The user is neither the owner of the file nor has an invitation to it. Append is not possible")
		}

		fn_suffix, file_encr_k, file_mac_k, err = userdata.inviteToFileMD(filename, dataJson)

		if err != nil {
			return err
		}
	}
	firstFile, err := userdata.decryptNode(fn_suffix, 1, file_encr_k, file_mac_k)

	if err != nil {
		return err
	}

	firstFile.Length += 1

	err = userdata.encryptAndMacNode(firstFile, file_encr_k, file_mac_k, fn_suffix, 1)

	if err != nil {
		return err
	}

	var tailFile File

	tailFile.Content = content
	tailFile.Length = -1
	tailFile.MM_MD = make(map[userlib.UUID][][]byte)

	err = userdata.encryptAndMacNode(tailFile, file_encr_k, file_mac_k, fn_suffix, firstFile.Length)

	if err != nil {
		return err
	}

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return nil, err
	}

	fn_suffix := userdata.FN_to_suffix[filename]
	var file_encrypt_k []byte
	var file_mac_k []byte

	if fn_suffix != nil {
		// The filename must be owned by the caller of this function
		fn_suffix, file_encrypt_k, file_mac_k, err = userdata.ownerFileMD(filename)

		if err != nil {
			return nil, err
		}
	} else {
		// The filename must be a file that the caller of this function is invited to
		jsonData, ok, err := userdata.userHasInvite(filename)

		if err != nil {
			return nil, err
		}

		if !ok {
			return nil, errors.New("User does not have invite")
		}

		fn_suffix, file_encrypt_k, file_mac_k, err = userdata.inviteToFileMD(filename, jsonData)
	}

	// Retrieve the very firstnode in the linked list
	firstFile, err := userdata.decryptNode(fn_suffix, 1, file_encrypt_k, file_mac_k)

	if err != nil {
		return nil, err
	}

	// Iterate through the length of the linked list and for each node upload the contents
	output_array := []byte{}
	length := firstFile.Length

	for curr_node := 1; curr_node <= length; curr_node++ {
		curr_file, err := userdata.decryptNode(fn_suffix, curr_node, file_encrypt_k, file_mac_k)

		if err != nil {
			return nil, err
		}

		output_array = append(output_array, curr_file.Content...)
	}

	return output_array, nil
}

func (userdata *User) encryptAndMacNode(curr_file File, f_encr_k []byte, f_mac_k []byte, fn_suffix []byte, curr_node int) (err error) {
	curr_node_byte_array, err := json.Marshal(curr_node)

	if err != nil {
		return err
	}

	// UUID -> UUID(H(fn_suffix + curr_node))
	str := append(fn_suffix, curr_node_byte_array...)
	hash_str_16 := last16Bytes(userlib.Hash(str))
	uuid_hash_str, err := uuid.FromBytes(hash_str_16)

	if err != nil {
		return err
	}

	file_json, err := json.Marshal(curr_file)

	if err != nil {
		return err
	}

	e1 := userlib.SymEnc(f_encr_k, userlib.RandomBytes(16), file_json)

	mac1, err := userlib.HMACEval(f_mac_k, e1)

	if err != nil {
		return err
	}

	e1_and_mac1 := map[string][]byte{"encryption": e1, "mac": mac1}

	e1_and_mac1_arr, err := json.Marshal(e1_and_mac1)

	if err != nil {
		return err
	}

	// Store <uuid_hash_str, e1 || mac1>
	userlib.DatastoreSet(uuid_hash_str, e1_and_mac1_arr)
	return nil

}

func (userdata *User) decryptNode(fn_suffix []byte, curr_node int, f_encr_k []byte, f_mac_k []byte) (curr_file File, err error) {
	empty_file := new(File)
	curr_node_byte_array, err := json.Marshal(curr_node)

	if err != nil {
		return *empty_file, err
	}

	// UUID -> UUID(H(fn_suffix + curr_node))
	str := append(fn_suffix, curr_node_byte_array...)
	hash_str_16 := last16Bytes(userlib.Hash(str))
	uuid_hash_str, err := uuid.FromBytes(hash_str_16)

	if err != nil {
		return *empty_file, err
	}

	dataJSON, ok := userlib.DatastoreGet(uuid_hash_str)

	if !ok {
		return *empty_file, errors.New("Could not locate the fileNode")
	}

	e1_and_mac1 := make(map[string][]byte)

	err = json.Unmarshal(dataJSON, &e1_and_mac1)

	if err != nil {
		return *empty_file, err
	}

	// Get encryption and mac object
	encrypt_obj := e1_and_mac1["encryption"]
	saved_mac_obj := e1_and_mac1["mac"]

	// Verify that the saved_mac_obj is the same as computed_mac_obj
	computed_mac_obj, err := userlib.HMACEval(f_mac_k, encrypt_obj)

	if err != nil {
		return *empty_file, err
	}

	if !userlib.HMACEqual(saved_mac_obj, computed_mac_obj) {
		return *empty_file, errors.New("The integrity of the fileNode cannot be verified")
	}

	dec_file := userlib.SymDec(f_encr_k, encrypt_obj)

	var currFile File
	err = json.Unmarshal(dec_file, &currFile)

	if err != nil {
		return *empty_file, err
	}

	return currFile, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	// Store temp ptr UUID = UUID(H(fileName + senderUsername + recipientUsername))
	userdata, err = GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return uuid.Nil, err
	}
	final_str := append([]byte(filename), []byte(userdata.Username)...)
	final_str = append(final_str, []byte(recipientUsername)...)
	last_16 := last16Bytes(userlib.Hash(final_str))
	invite_uuid, err := uuid.FromBytes(last_16)

	if err != nil {
		return uuid.Nil, err
	}

	_, createdInvitation := userlib.DatastoreGet(invite_uuid)

	if createdInvitation {
		return invite_uuid, nil
	}

	// Only owner knows the fn_suffix so if it is not nil the owner must be calling this function
	var fn_suffix = userdata.FN_to_suffix[filename]

	_, contains_invite, err := userdata.userHasInvite(filename)

	if err != nil {
		return uuid.Nil, err
	}

	if fn_suffix == nil && !contains_invite {
		return uuid.Nil, errors.New("This user does not have access to file they are attempting to share")
	}

	if err != nil {
		return uuid.Nil, err
	}

	var mm_encr_k []byte
	var mm_mac_k []byte
	var mm_uuid userlib.UUID
	var mm_obj MiddleMan
	if fn_suffix != nil {
		// Since owner is calling the function we should be creating a new middle man object

		// We will fill the middle man object with meta data of file object
		fn_suffix, f_encr_k, f_mac_k, err := userdata.ownerFileMD(filename)

		if err != nil {
			return uuid.Nil, err
		}

		mm_obj.Suffix = fn_suffix
		mm_obj.File_encr_k = f_encr_k
		mm_obj.File_mac_k = f_mac_k
		mm_obj.Users = make(map[string]uuid.UUID)

		// Generate middle man keys
		mm_encr_k = userlib.RandomBytes(16)
		mm_mac_k = userlib.RandomBytes(16)
		mm_uuid, err = uuid.FromBytes(userlib.RandomBytes(16))

		if err != nil {
			return uuid.Nil, err
		}

		// Store Middle Man meta data in file object
		first_node, err := userdata.decryptNode(fn_suffix, 1, f_encr_k, f_mac_k)

		if err != nil {
			return uuid.Nil, err
		}

		first_node.MM_MD[mm_uuid] = [][]byte{mm_encr_k, mm_mac_k}

		err = userdata.encryptAndMacNode(first_node, f_encr_k, f_mac_k, fn_suffix, 1)

		if err != nil {
			return uuid.Nil, err
		}
	} else {
		e1_and_mac1_json, contains_invite, err := userdata.userHasInvite(filename)

		if err != nil {
			return uuid.Nil, err
		}
		// If the function is caller is not the owner of the file they must have an invite in order to call the function
		if !contains_invite {
			return uuid.Nil, errors.New("Caller of function does not have access to the file")
		} else {
			// At this point we can assume the user can access the file through their invite object
			mm_uuid, mm_encr_k, mm_mac_k, err = userdata.inviteToMM_MD(e1_and_mac1_json)

			if err != nil {
				return uuid.Nil, err
			}

			mm_obj, err = userdata.inviteToMM(e1_and_mac1_json)

			if err != nil {
				return uuid.Nil, err
			}
		}
	}

	// Create the new invite object
	var curr_inv Invite
	curr_inv.MM_id = mm_uuid
	curr_inv.MM_ek = mm_encr_k
	curr_inv.MM_mk = mm_mac_k

	// Find the public key of the recipent KS(H(username + "RSA key"))
	recipient_public_key, err := getPublicRSAKey(recipientUsername)

	if err != nil {
		return uuid.Nil, err
	}

	err = userdata.encryptAndSigInvite(curr_inv, invite_uuid, recipient_public_key, userdata.SignKey)

	if err != nil {
		return uuid.Nil, err
	}

	// The recipient is user of this middle man object now
	mm_obj.Users[recipientUsername] = invite_uuid
	err = encryptAndMacMM(mm_obj, mm_encr_k, mm_mac_k, mm_uuid)

	if err != nil {
		return uuid.Nil, err
	}

	return invite_uuid, nil
}

func (userdata *User) encryptAndSigInvite(invite_obj Invite, invite_uuid userlib.UUID, encr_k userlib.PKEEncKey, sig_k userlib.DSSignKey) (err error) {
	invite_obj_byte_arr, err := json.Marshal(invite_obj)

	if err != nil {
		return err
	}

	e1, err := userlib.PKEEnc(encr_k, invite_obj_byte_arr)

	if err != nil {
		return err
	}

	sig1, err := userlib.DSSign(sig_k, e1)

	if err != nil {
		return err
	}

	e1_and_sig1 := map[string][]byte{"encryption": e1, "signature": sig1}

	e1_and_sig1_arr, err := json.Marshal(e1_and_sig1)

	if err != nil {
		return err
	}

	userlib.DatastoreSet(invite_uuid, e1_and_sig1_arr)

	return nil
}

// This function returns mm meta data from invite json object
func (userdata *User) inviteToMM_MD(dataJSON []byte) (mm_uuid uuid.UUID, mm_encr_k []byte, mm_mac_k []byte, err error) {
	e1_and_sig1 := make(map[string][]byte)

	err = json.Unmarshal(dataJSON, &e1_and_sig1)

	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	// Get the public key of current user to verify digital signature UUID -> H(username)
	verify_key, err := getVerifyKey(userdata.Username)

	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	// Decrypt invite object
	my_invite, err := userdata.decryptAndVerifyInvite(dataJSON, userdata.Secretkey, verify_key)

	if err != nil {
		return uuid.Nil, nil, nil, err
	}

	return my_invite.MM_id, my_invite.MM_ek, my_invite.MM_mk, nil
}

// Return the middle man object from the invite object data json
func (userdata *User) inviteToMM(dataJSON []byte) (mm_obj MiddleMan, err error) {
	emptyMM := new(MiddleMan)

	mm_uuid, mm_encr_k, mm_mac_k, err := userdata.inviteToMM_MD(dataJSON)

	if err != nil {
		return *emptyMM, err
	}

	// Get middleman object
	dataJSON, ok := userlib.DatastoreGet(mm_uuid)
	if !ok {
		return *emptyMM, errors.New("Unable to retrieve the middle man object corresponding to this invite object")
	}

	// Middle man encryption and mac
	e1_and_mac1 := make(map[string][]byte)

	err = json.Unmarshal(dataJSON, &e1_and_mac1)

	if err != nil {
		return *emptyMM, err
	}

	// Get encryption and mac object for middleman object
	encrypt_obj := e1_and_mac1["encryption"]
	saved_mac_obj := e1_and_mac1["mac"]

	computed_mac_obj, err := userlib.HMACEval(mm_mac_k, encrypt_obj)

	if err != nil {
		return *emptyMM, err
	}

	// Verify that macs are valid for middle man object
	if !userlib.HMACEqual(saved_mac_obj, computed_mac_obj) {
		return *emptyMM, errors.New("Mac comparison of middleman object was unsuccessful")
	}

	// Decrypt middleman object
	var mm_json []byte = userlib.SymDec(mm_encr_k, encrypt_obj)

	var my_middle_man MiddleMan

	err = json.Unmarshal(mm_json, &my_middle_man)

	if err != nil {
		return *emptyMM, err
	}

	return my_middle_man, nil
}

func encryptAndMacMM(obj MiddleMan, encr_k []byte, mac_k []byte, uuid userlib.UUID) (err error) {
	json_obj, err := json.Marshal(obj)

	if err != nil {
		return err
	}

	var e1 = userlib.SymEnc(encr_k, userlib.RandomBytes(16), json_obj)
	mac1, err := userlib.HMACEval(mac_k, e1)

	if err != nil {
		return err
	}

	e1_and_mac1 := map[string][]byte{"encryption": e1, "mac": mac1}

	e1_and_mac1_arr, err := json.Marshal(e1_and_mac1)

	if err != nil {
		return err
	}

	userlib.DatastoreSet(uuid, e1_and_mac1_arr)
	return nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// TODO: WE NEED TO VERIFY THAT:
	// The caller already has a file with the given filename in their personal file namespace.
	// The invitation is no longer valid due to revocation.

	userdata, err := GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return err
	}

	var fn_suffix = userdata.FN_to_suffix[filename]
	_, contains_invite, err := userdata.userHasInvite(filename)

	if err != nil {
		return err
	}

	if fn_suffix != nil || contains_invite {
		return errors.New("This file already exists in users personal namespace")
	}

	// Retrieve the encrypted invitation object and digital signature
	e1_and_sig1_json, ok := userlib.DatastoreGet(invitationPtr)

	if !ok {
		return errors.New("Invalid uuid for invitationPtr")
	}

	// Find senderUser's digital signature verification key from key store -> KeyStore.get(H(username + "Signature key"))
	sender_verify_key, err := getVerifyKey(senderUsername)

	if err != nil {
		return err
	}

	// Decrypt the invitation object with recipient private RSA key and verify the digital signature with sender verify_key
	invite_obj, err := userdata.decryptAndVerifyInvite(e1_and_sig1_json, userdata.Secretkey, sender_verify_key)

	if err != nil {
		return err
	}

	// Create a new uuid for the e1_and_sig1 invite object -> UUID = UUID(H(fileName + username + "invite"))
	final_str := append([]byte(filename), []byte(userdata.Username)...)
	final_str = append(final_str, []byte("invite")...)
	last_16 := last16Bytes(userlib.Hash(final_str))
	new_uuid, err := uuid.FromBytes(last_16)

	if err != nil {
		return errors.New("Cannot create a new uuid for the invite object")
	}

	recipient_public_encr_k, err := getPublicRSAKey(userdata.Username)

	if err != nil {
		return err
	}

	userdata.encryptAndSigInvite(invite_obj, new_uuid, recipient_public_encr_k, userdata.SignKey)

	// Delete old invitationPtr
	userlib.DatastoreDelete(invitationPtr)

	invite_json, ok := userlib.DatastoreGet(new_uuid)

	if !ok {
		return errors.New("The invite object is not being stored in the correct location")
	}

	mm_obj, err := userdata.inviteToMM(invite_json)

	if err != nil {
		return err
	}

	// Users dictionary should associate the user with the new invitation uuid
	mm_obj.Users[userdata.Username] = new_uuid

	// Store new mac object
	encryptAndMacMM(mm_obj, invite_obj.MM_ek, invite_obj.MM_mk, invite_obj.MM_id)

	return nil
}

func getVerifyKey(username string) (vk userlib.DSVerifyKey, err error) {
	var username_arr = []byte(username)
	var ds_key = []byte("Signature key")
	var final_str = append(username_arr, ds_key...)
	var last_16 = last16Bytes(userlib.Hash(final_str))
	var myString = string(last_16[:])
	verify_key, ok := userlib.KeystoreGet(myString)

	if !ok {
		return verify_key, errors.New("Could not retrieve the verification key for this user")
	}

	return verify_key, nil
}

// Get the public RSA key for a user based on their username
func getPublicRSAKey(username string) (ek userlib.PKEEncKey, err error) {
	var final_str = append([]byte(username), "RSA Key"...)
	var hash_16 = last16Bytes(userlib.Hash([]byte(final_str)))
	recipientStr := string(hash_16[:])
	recipient_public_key, ok := userlib.KeystoreGet(recipientStr)

	if !ok {
		return recipient_public_key, errors.New("Cannot retrieve public RSA key for this user")
	}

	return recipient_public_key, nil
}

// Decrypts and verifies the signature of an invite object
func (userdata *User) decryptAndVerifyInvite(dataJSON []byte, decrypt_k userlib.PKEDecKey, verify_k userlib.DSVerifyKey) (obj Invite, err error) {
	// Retrieve the e1_and_sig1 dictionary
	empty_invite := new(Invite)
	e1_and_sig1 := make(map[string][]byte)

	err = json.Unmarshal(dataJSON, &e1_and_sig1)

	if err != nil {
		return *empty_invite, err
	}

	encrypt_obj := e1_and_sig1["encryption"]
	sig_obj := e1_and_sig1["signature"]

	// Verify the digital signature with the senderUser's verification key
	err = userlib.DSVerify(verify_k, encrypt_obj, sig_obj)

	if err != nil {
		return *empty_invite, errors.New("The integrity of the encrypted invite object cannot be verified")
	}

	// Decrypt and Return the invite object
	invite_json, err := userlib.PKEDec(decrypt_k, encrypt_obj)

	if err != nil {
		return *empty_invite, errors.New("Could not decrypt the invite object")
	}

	var invite_obj Invite
	err = json.Unmarshal(invite_json, &invite_obj)

	if err != nil {
		return *empty_invite, errors.New("Could not unmarshal the invite json object")
	}

	return invite_obj, nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	userdata, err := GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return errors.New("Unable to fetch user data")
	}

	var old_fn_suffix = userdata.FN_to_suffix[filename]
	var old_num_revokes = userdata.FN_to_numRevokes[filename]

	if old_fn_suffix == nil || old_num_revokes == nil {
		return errors.New("The revoke access function is being called by someone who is not the owner")
	} else {
		// Generate file's old meta data needed to decrypt the file node
		old_fn_suffix, old_encr_k, old_mac_k, err := userdata.ownerFileMD(filename)

		if err != nil {
			return errors.New("Unable to retrieve the file's old meta data")
		}

		// Generate new num_revokes and new_fn suffix and store in user struct
		new_num_revokes := userlib.RandomBytes(16)
		new_fn_suffix := userlib.RandomBytes(16)

		userdata.FN_to_suffix[filename] = new_fn_suffix
		userdata.FN_to_numRevokes[filename] = new_num_revokes

		userdata.encryptAndMacUserObj()

		// Get the new keys for the file based on new_fn_suffix and new_num_revokes we saved in user struct
		new_encr_k, new_mac_k, err := userdata.ownerFileKeys(filename)

		if err != nil {
			return err
		}

		// Determine the length of the file linked list
		first_node, err := userdata.decryptNode(old_fn_suffix, 1, old_encr_k, old_mac_k)

		if err != nil {
			return err
		}

		node_length := first_node.Length

		// Iterate through each node in the file linked list and re-encrypt each file node with the new keys
		for node_num := 1; node_num <= node_length; node_num++ {
			curr_file, err := userdata.decryptNode(old_fn_suffix, node_num, old_encr_k, old_mac_k)

			if err != nil {
				return err
			}

			// Delete the oldfile entry from the database
			old_file_uuid, err := retrieveFileUUID(string(old_fn_suffix), node_num)
			userlib.DatastoreDelete(old_file_uuid)

			if err != nil {
				return err
			}

			err = userdata.encryptAndMacNode(curr_file, new_encr_k, new_mac_k, new_fn_suffix, node_num)

			if err != nil {
				return err
			}
		}

		// Iterate through the middle men -> for the ith middle man -> if contains recipientUser then delete
		// else update the middle man keys to point to the new file object

		to_delete_id := uuid.Nil
		to_delete_obj := *new(MiddleMan)

		for mm_id, mm_md := range first_node.MM_MD {
			curr_mm, err := getMM(mm_id, mm_md[0], mm_md[1])

			if err != nil {
				return err
			}

			if curr_mm.containsUser(recipientUsername) {
				to_delete_id = mm_id
				to_delete_obj = curr_mm
			} else {
				curr_mm.Suffix = new_fn_suffix
				curr_mm.File_encr_k = new_encr_k
				curr_mm.File_mac_k = new_mac_k

				err = encryptAndMacMM(curr_mm, mm_md[0], mm_md[1], mm_id)

				if err != nil {
					return err
				}
			}
		}

		if to_delete_id == uuid.Nil {
			return errors.New("Could not find recipientUser in list of shared users")
		} else {
			deleteAllMMInvitations(to_delete_obj)
			userlib.DatastoreDelete(to_delete_id)

			// Update the file node's middle men hashmap
			delete(first_node.MM_MD, to_delete_id)
			if err != nil {
				return err
			}

			// Re-encrypt the file node
			err = userdata.encryptAndMacNode(first_node, new_encr_k, new_mac_k, new_fn_suffix, 1)

			if err != nil {
				return err
			}
		}

		return nil
	}
}

func deleteAllMMInvitations(mm_obj MiddleMan) {
	for _, uuid := range mm_obj.Users {
		// element is the element from someSlice for where we are
		userlib.DatastoreDelete(uuid)
	}
}

func (mm_data MiddleMan) containsUser(recipientUsername string) (containsUser bool) {
	for username, _ := range mm_data.Users {
		// element is the element from someSlice for where we are

		if username == recipientUsername {
			return true
		}
	}
	return false
}

func getMM(id userlib.UUID, encr_k []byte, mac_k []byte) (mm MiddleMan, err error) {
	empty_mm := new(MiddleMan)
	e1_and_mac1_json, ok := userlib.DatastoreGet(id)

	if !ok {
		return *empty_mm, errors.New("The id passed in is not in data store for this middle man object")
	}

	// Retrieve the encryption and mac for this middle man object
	e1_and_mac1 := make(map[string][]byte)

	err = json.Unmarshal(e1_and_mac1_json, &e1_and_mac1)

	if err != nil {
		return *empty_mm, err
	}

	encrypt_obj := e1_and_mac1["encryption"]
	saved_mac_obj := e1_and_mac1["mac"]

	// Verify that the mac of the encrypted mm object is valid
	computed_mac_obj, err := userlib.HMACEval(mac_k, encrypt_obj)

	if err != nil {
		return *empty_mm, err
	}

	if !userlib.HMACEqual(saved_mac_obj, computed_mac_obj) {
		return *empty_mm, errors.New("The stored mac object is invalid for this middle man object")
	}

	// Decrypt the middle man object and return the output
	mm_json := userlib.SymDec(encr_k, encrypt_obj)

	var mm_obj MiddleMan

	err = json.Unmarshal(mm_json, &mm_obj)

	if err != nil {
		return *empty_mm, err
	}

	return mm_obj, nil
}

func retrieveFileUUID(fn_suffix string, curr_node int) (id userlib.UUID, err error) {
	node_num_json, err := json.Marshal(curr_node)

	if err != nil {
		return uuid.Nil, err
	}

	final_str := append([]byte(fn_suffix), []byte(node_num_json)...)
	last_16 := last16Bytes(userlib.Hash(final_str))
	uuid_val, err := uuid.FromBytes(last_16)

	if err != nil {
		return uuid.Nil, err
	}

	return uuid_val, nil
}

func (userdata *User) ownerFileKeys(filename string) (file_encr_k []byte, file_mac_k []byte, err error) {
	userdata, err = GetUser(userdata.Username, userdata.Password)

	if err != nil {
		return nil, nil, err
	}

	var fn_suffix = userdata.FN_to_suffix[filename]
	var num_revokes = userdata.FN_to_numRevokes[filename]

	if fn_suffix == nil || num_revokes == nil {
		return nil, nil, errors.New("Cannot retrieve keys because user is not owner of file")
	}

	var root_k = userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Compute hashKDF keys to verify encryption/mac
	var encrypt_add = []byte("encryption key")
	var mac_add = []byte("mac key")
	var username_arr = []byte(userdata.Username)

	// HashKDF(root_k, filename + username + encyption key + num_revokes)
	full_hashkdf := append([]byte(filename), username_arr...)
	full_hashkdf = append(full_hashkdf, encrypt_add...)
	full_hashkdf = append(full_hashkdf, num_revokes...)

	encr_k, err := userlib.HashKDF(root_k, full_hashkdf)
	encr_k = last16Bytes(encr_k)

	if err != nil {
		return nil, nil, err
	}

	// HashKDF(root_k, filename + username + mac key + num_revokes)
	full_hashkdf = append([]byte(filename), username_arr...)
	full_hashkdf = append(full_hashkdf, mac_add...)
	full_hashkdf = append(full_hashkdf, num_revokes...)
	mac_k, err := userlib.HashKDF(root_k, full_hashkdf)
	mac_k = last16Bytes(mac_k)

	if err != nil {
		return nil, nil, err
	}

	return encr_k, mac_k, nil
}
