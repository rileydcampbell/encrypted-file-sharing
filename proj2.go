package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"

	// optional
	_ "strconv"

	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg
	// see someUsefulThings() below
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	// fmt.Printf("HAHAHAHHAHAHAHHHHHASHFSDDFS \n\n\nn")
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
    	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)

}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
// func bytesToUUID(data []byte) (ret uuid.UUID) {
// 	for x := range ret {
// 		ret[x] = data[x]
// 	}
// 	return
// }

// The structure definition for a user record
type User struct {
	Username string
	PrivatePKEKey userlib.PKEDecKey //The public ecryption key for RSA will be stored in keystore
	PrivateDSSignKey userlib.DSSignKey // The public verification key will be stored in keystore
	FileTable uuid.UUID
	FileTableKey []byte
}

//Used for the File structs to point to one another
type uuidAndFileKey struct {
	FileLoc uuid.UUID
	FileKey []byte
}
//Can be decrypted and verified using the fileTable key found in each user struct
type FileTable struct {
	FileNameMapping map[string]uuidAndFileKey
}
//Can be decrypted and verified using the FileKey found in each of the map objects in each user's FileTable
type File struct {
	FileIndexMapping map[int]uuidAndFileKey
}
//Can be decrypted and verified using the FileKey found in each of the map objects in each File struct
type FileCompartment struct {
	Data []byte
}

//gets new keys by HMAC'ing the salted Password with different phrases and taking the first 16 bytes

func getKeys(masterKey []byte) (hmacKey []byte, symEncryptKey []byte, err error) {
	if (len(masterKey) != 16) {
		return nil, nil, errors.New("HMACKey is not 16 bytes in getKeys()")
	}
	hmacKey, _ = userlib.HMACEval(masterKey, []byte("This is the HMAC Key"))
	symEncryptKey, _ = userlib.HMACEval(masterKey, []byte("This is the SYM Encrypt Key"))
	hmacKey = hmacKey[:16]
	symEncryptKey = symEncryptKey[:16]
	return hmacKey, symEncryptKey, nil
}

func AuthenticatedEncryption(masterKey []byte, msgToEncrypt []byte) (fullyEncodedBytes []byte, err error){
	//Assuming that SymEnc and HMACEval will not error usually
	hmacKey, symEncryptKey, e := getKeys(masterKey)
	if e != nil {
		return nil, e
	}
	randIV := userlib.RandomBytes(16)
	encodedBytes := userlib.SymEnc(symEncryptKey, randIV, msgToEncrypt)
	hmacEncodedBytes, _ := userlib.HMACEval(hmacKey, encodedBytes)
	fullyEncodedBytes = append(encodedBytes, hmacEncodedBytes...)
	return fullyEncodedBytes, nil
}

func AuthenticatedDecryption(masterKey []byte, msgToDecrypt []byte) (decryptedMsg []byte, err error) {
	hmacKey, symEncryptKey, e := getKeys(masterKey)
	if e != nil {
		return nil, e
	}
	if len(msgToDecrypt) < 64 {
		return nil, errors.New("Length of the mesage is too short (<64)")
	}
	retrievedHMAC := msgToDecrypt[len(msgToDecrypt) - 64:]
	cipherText := msgToDecrypt[:len(msgToDecrypt) - 64]
	newHMAC, _ := userlib.HMACEval(hmacKey, cipherText)
	// if hmacErr != nil {
	// 	return nil, hmacErr
	// }

	isValidData := userlib.HMACEqual(retrievedHMAC, newHMAC)
	if isValidData == false {
		return nil, errors.New("HMAC's don't match. Data is altered or missing")
		//throw error here but shouldn't error out yet
	}
	decryptedMsg = userlib.SymDec(symEncryptKey, cipherText)
	return decryptedMsg, nil
}

func CreateFileTable() (fileTableUUID uuid.UUID, fileTableKey []byte, err error){
	//Create FileTable struct and the fileNameMapping attribute of FileTable
	var ft FileTable
	FileNameMapping := map[string]uuidAndFileKey{}
	ft = FileTable{FileNameMapping}

	fileTableUUID = uuid.New()

	//use this value HMAC'd with phrasel to retrieve the HMAC and Sym encrption for a fileTable
	fileTableKey = userlib.RandomBytes(16)
	fileTableHMACKey, fileTableSymKey, e := getKeys(fileTableKey)
	if e != nil {
		return fileTableUUID, fileTableKey, e
	}

	jsonBytesFileTable, marshErr := json.Marshal(ft)
	if marshErr != nil {
		return fileTableUUID, fileTableKey, marshErr
	}
	randIV := userlib.RandomBytes(16)
	encodedBytes := userlib.SymEnc(fileTableSymKey, randIV, jsonBytesFileTable)
	hmacEncodedBytes, hmacErr := userlib.HMACEval(fileTableHMACKey, encodedBytes)
	if hmacErr != nil {
		return fileTableUUID, fileTableKey, hmacErr
	}
	fullyEncodedBytes := append(encodedBytes, hmacEncodedBytes...)

	userlib.DatastoreSet(fileTableUUID, fullyEncodedBytes)
	return fileTableUUID, fileTableKey, nil
}

func getUserId(saltedPassword []byte) (userID uuid.UUID) {
	userUUIDKey, _ := userlib.HMACEval(saltedPassword, []byte("This is the UUID"))
	userUUIDKey = userUUIDKey[:16]
	userID, _ = uuid.FromBytes(userUUIDKey)
	return userID
}
// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	saltedPassword := userlib.Argon2Key([]byte(password), []byte(username), 16)

	//Get all vars from salted password
	userUUID := getUserId(saltedPassword)

	//Creating the file table
	fileTableUUID, fileTableKey, e := CreateFileTable()
	if e != nil {
		return &userdata, e
	}

	//pkEncryptKey and dsVerifyKey are the public keys (Put on datastore)
	//pkDecryptKey and dsSignKey are the private keys
	dsSignKey, dsVerifyKey, _ := userlib.DSKeyGen()
	pkEncryptKey, pkDecryptKey, _ := userlib.PKEKeyGen()
	userlib.KeystoreSet(username + "PKEEncKey", pkEncryptKey)
	userlib.KeystoreSet(username + "DSVerifyKey", dsVerifyKey)

	userdata = User{username, pkDecryptKey, dsSignKey, fileTableUUID, fileTableKey}
	//Process to encode the user struct
	jsonBytesUserData, _ := json.Marshal(userdata)
	// if marshErr != nil {
	// 	return &userdata, marshErr
	// }
	fullyEncodedBytes, _ :=  AuthenticatedEncryption(saltedPassword, jsonBytesUserData)
	// if encErr != nil {
	// 	return &userdata, encErr
	// }
	userlib.DatastoreSet(userUUID, fullyEncodedBytes)

	return &userdata, nil
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	//haven't implemented error checking yet
	saltedPassword := userlib.Argon2Key([]byte(password), []byte(username), 16)

	userUUID := getUserId(saltedPassword)

	//checks for user
	allUserBytes, ok := userlib.DatastoreGet(userUUID)
	if ok == false {
		return &userdata, errors.New("DatastoreGet error: Wrong username or password")
	}

	decryptedMsg, e := AuthenticatedDecryption(saltedPassword, allUserBytes)
	if e != nil {
		return userdataptr, e
	}
	unmarshErr := json.Unmarshal(decryptedMsg, &userdata)
	if unmarshErr != nil {
		return userdataptr, unmarshErr
	}
	return userdataptr, nil
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	//no error handling here as this should never error
	fileTable, _ := getFileTable(userdata)

	//Map filename to a uuidAndFileKey struct
	fileUUID, fileKey := getUUIDandRandomBits()
	fileUUIDAndFileKey := uuidAndFileKey{fileUUID, fileKey}
	fileTable.FileNameMapping[filename] = fileUUIDAndFileKey
	// userlib.DebugMsg("fileUUID")

	//Marshal and Encrypt user FileTable then Datastore the new table back to the UUID
	fullyEncodedBytes, _ := json.Marshal(fileTable)
	encryptedFileTable, _ := AuthenticatedEncryption(userdata.FileTableKey, fullyEncodedBytes)
	userlib.DatastoreSet(userdata.FileTable, encryptedFileTable)

	//Map index in new File struct to a uuidAndFileKey struct
	fileCompartmentUUID, fileCompartmentKey := getUUIDandRandomBits()
	fileCompartmentUUIDAndFileKey := uuidAndFileKey{fileCompartmentUUID, fileCompartmentKey}
	FileIndexMapping := map[int]uuidAndFileKey{}
	var file File
	file = File{FileIndexMapping}
	file.FileIndexMapping[0] = fileCompartmentUUIDAndFileKey

	//Marshal and Encrypt File then Datastore the new File to the UUID specified in the FileTable
	fileEncodedBytes, _ := json.Marshal(file)
	encryptedFile, _ := AuthenticatedEncryption(fileKey, fileEncodedBytes)
	userlib.DatastoreSet(fileUUID, encryptedFile)

	//Marshal and Encrypt FileCompartment then Datastore the new FileCompartment to the UUID specified in the File
	var FileComp FileCompartment
	FileComp = FileCompartment{data}
	fileCompartmentEncodedBytes, _ := json.Marshal(FileComp)
	encryptedData, _ := AuthenticatedEncryption(fileCompartmentKey, fileCompartmentEncodedBytes)
	userlib.DatastoreSet(fileCompartmentUUID, encryptedData)
	return
}

func ValidateDataStoreGet(ok bool) (err error){
	if ok == false {
		userlib.DebugMsg("DataStoreGet Failure.")
		return errors.New("DataStoreGet Failure.")
	}
	return nil
}

func getUUIDandRandomBits() (uuid.UUID, []byte) {
	return uuid.New(), userlib.RandomBytes(16)
}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	fileTable, fileTableErr := getFileTable(userdata)
	if fileTableErr != nil {
		return fileTableErr
	}

	file, ok := getFile(fileTable, filename)
	if ok == false {
		return errors.New("No such file exists")
	}

	fileUUIDAndKey, ok := fileTable.FileNameMapping[filename]
	if ok == false {
		return errors.New("No such fileuuidandkey struct exists")
	}
	nextIndexInFileIndexMapping := len(file.FileIndexMapping)

	//create a new compartment
	newFileCompartmentUUID, newFileCompartmentKey := getUUIDandRandomBits()
	newFileCompartmentUUIDAndFileKey := uuidAndFileKey{newFileCompartmentUUID, newFileCompartmentKey}
	file.FileIndexMapping[nextIndexInFileIndexMapping] = newFileCompartmentUUIDAndFileKey
	var FileComp FileCompartment
	FileComp = FileCompartment{data}
	fileCompartmentEncodedBytes, marshError := json.Marshal(FileComp)
	if marshError != nil {
		return marshError
	}
	encryptedData, authErr := AuthenticatedEncryption(newFileCompartmentKey, fileCompartmentEncodedBytes)
	if authErr != nil {
		return authErr
	}
	userlib.DatastoreSet(newFileCompartmentUUID, encryptedData)

	//reencrypt File Struct with updated FileIndexMapping
	fileEncodedBytes, marshError := json.Marshal(file)
	if marshError != nil {
		return marshError
	}
	encryptedFile, authErr:= AuthenticatedEncryption(fileUUIDAndKey.FileKey, fileEncodedBytes)
	if authErr != nil {
		return authErr
	}
	userlib.DatastoreSet(fileUUIDAndKey.FileLoc, encryptedFile)

	return nil
}

func getFileTable (userdata* User) (fileTable FileTable, err error) {
	fileTableBytes, ok := userlib.DatastoreGet(userdata.FileTable)
	if ValidateDataStoreGet(ok) != nil {
		return FileTable{}, errors.New("Error getting File Table from user struct")
	}
	decryptedFileTable, decryptErr := AuthenticatedDecryption(userdata.FileTableKey, fileTableBytes)
	if decryptErr != nil {
		return FileTable{}, decryptErr
	}
	unmarshErr := json.Unmarshal(decryptedFileTable, &fileTable)
	if unmarshErr != nil {
		return FileTable{}, unmarshErr
	}
	return fileTable, nil
}

func getFile (fileTable FileTable, filename string) (file File, ok bool){
	fileUUIDAndKey, ok := fileTable.FileNameMapping[filename]
	if ok == false {
		return File{}, false
	}
	//file struct
	encryptedFileStruct, ok := userlib.DatastoreGet(fileUUIDAndKey.FileLoc)
	if ok == false {
		return File{}, false
	}
	decryptedFileStruct, decryptErr := AuthenticatedDecryption(fileUUIDAndKey.FileKey, encryptedFileStruct)
	if decryptErr != nil {
		return File{}, false
	}
	var currFile File
	_ = json.Unmarshal(decryptedFileStruct, &currFile)
	return currFile, true
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	fileTable, fileTableErr := getFileTable(userdata)
	if fileTableErr != nil {
		return []byte("nil"), fileTableErr
	}
	file, ok := getFile(fileTable, filename)
	if ok == false {
		return []byte("nil"), errors.New("No such file exists")
	}
	//of type UUIDAndFileKey
	lengthFileComponents := len(file.FileIndexMapping)
	var resFile []byte
	for i := 0; i < lengthFileComponents; i++ {
		currFileComponent := file.FileIndexMapping[i]
		encryptedFileCompartment, getErr := userlib.DatastoreGet(currFileComponent.FileLoc)
		if getErr == false {
			return resFile, errors.New("Error getting file compartment")
		}
		decryptedFileCompartment, decryptErr := AuthenticatedDecryption(currFileComponent.FileKey, encryptedFileCompartment)
		if decryptErr != nil {
			return resFile, decryptErr
		}
		var fileComp FileCompartment
		unmarshErr := json.Unmarshal(decryptedFileCompartment, &fileComp)
		if unmarshErr != nil {
			return resFile, unmarshErr
		}
		resFile = append(resFile, fileComp.Data...)
	}
	return resFile, nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (
	magic_string string, err error) {

	senderFileTable, fileTableErr := getFileTable(userdata)
	if fileTableErr != nil {
		return "bad magic string", fileTableErr
	}
	//file struct
	fileUUIDAndKey, ok := senderFileTable.FileNameMapping[filename]
	if ok == false {
		return "bad magic string", errors.New("File being shared does not exist")
	}

	//magic string should be the encrypted (using RSA) sharing Record struct
	//need to figure out file name
	jsonBytesSharedRecord, unmarshErr := json.Marshal(fileUUIDAndKey)
	if unmarshErr != nil {
		return "unmarsh",unmarshErr
	}

	recieverRSAPublicEncKey, ok := userlib.KeystoreGet(recipient + "PKEEncKey")
	if ok == false {
		return "Error", errors.New("Recipient does not have PKEEncey")
	}

	magicStringEncrypted, pkErr := userlib.PKEEnc(recieverRSAPublicEncKey, jsonBytesSharedRecord)
	if pkErr != nil {
		return "Err", pkErr
	}
	digitalSignature, dsErr := userlib.DSSign(userdata.PrivateDSSignKey, magicStringEncrypted)
	if dsErr != nil {
		return "err", dsErr
	}
	magic_string_bytes := append(magicStringEncrypted, digitalSignature...)
	return string(magic_string_bytes), nil
}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	magic_string string) error {
	
	magicStringBytes := []byte(magic_string)
	if len(magicStringBytes) <= 256 {
		return errors.New("Magic string is much too short")
	}
	retrievedSignature := magicStringBytes[len(magicStringBytes) - 256:]
	magicStringEncrypted := magicStringBytes[:len(magicStringBytes) - 256]
	publicVerifyKey, e := userlib.KeystoreGet(sender + "DSVerifyKey")
	if e == false {
		return errors.New("There was an error getting the verify key")
	}
	verifyError := userlib.DSVerify(publicVerifyKey, magicStringEncrypted, retrievedSignature)
	if verifyError != nil {
		return errors.New("This is an error in verifying the message")
	}
	decryptedMagicString, pkdec := userlib.PKEDec(userdata.PrivatePKEKey, magicStringEncrypted)
	if pkdec != nil {
		return pkdec
	}

	var sharedInfo uuidAndFileKey
	unmarshErr := json.Unmarshal(decryptedMagicString, &sharedInfo)
	if unmarshErr != nil {
		return unmarshErr
	}
	fileTable, fileTableErr := getFileTable(userdata)
	if fileTableErr != nil {
		return fileTableErr
	}
	//Need check here to see if file name already exists
	_, ok := fileTable.FileNameMapping[filename] 
	if ok == true {
		return errors.New("This filename already exists for the recipient")
	}

	fileTable.FileNameMapping[filename] = sharedInfo

	encryptedFileTable, unmarsh := json.Marshal(fileTable)
	if unmarsh != nil {
		return unmarsh
	}
	encryptedFile, authErr := AuthenticatedEncryption(userdata.FileTableKey, encryptedFileTable)
	if authErr != nil {
		return authErr
	}
	userlib.DatastoreSet(userdata.FileTable, encryptedFile)

	return nil
}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {
	fileTable, fileTableErr := getFileTable(userdata)
	if fileTableErr != nil {
		return fileTableErr
	}

	fileUUIDAndKey, ok := fileTable.FileNameMapping[filename]
	if ok == false {
		return errors.New("FileTable does not exist")
	}

	file, ok := getFile(fileTable, filename)
	if ok == false {
		return errors.New("File being revoked does not exist")
	}
	userlib.DatastoreDelete(fileUUIDAndKey.FileLoc)
	fileUUID, fileKey := getUUIDandRandomBits()
	newFileUUIDAndFileKey := uuidAndFileKey{fileUUID, fileKey}

	encodedFileBytes, _ := json.Marshal(file)
	encryptedFile, authErr := AuthenticatedEncryption(newFileUUIDAndFileKey.FileKey,encodedFileBytes)
	if authErr != nil {
		return authErr
	}

	userlib.DatastoreSet(newFileUUIDAndFileKey.FileLoc, encryptedFile)
	fileTable.FileNameMapping[filename] = newFileUUIDAndFileKey
	encodedFileTable, _ := json.Marshal(fileTable)
	encryptedFileTable, authErr := AuthenticatedEncryption(userdata.FileTableKey, encodedFileTable)
	if authErr != nil {
		return authErr
	}
	userlib.DatastoreSet(userdata.FileTable, encryptedFileTable)
	return nil
}
