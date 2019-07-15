package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	"testing"
	"reflect"
	"github.com/nweaver/cs161-p2/userlib"
	"encoding/json"
	// _ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)


func TestInit(t *testing.T) {
	t.Log("Initialization test")

	// You may want to turn it off someday
	// userlib.SetDebugStatus(true)
	someUsefulThings()
	// userlib.SetDebugStatus(false)
	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	// t.Log("Got user", u)
	_ = u
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestAppend(t *testing.T) {
	// And some more tests, because
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}

	v := []byte("This is a test")
	vAppended := []byte(" and this is another appended portion")
	u.StoreFile("file1", v)
	u.AppendFile("file1", vAppended)

	fullFile := append(v, vAppended...)
	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
	}
	if !reflect.DeepEqual(fullFile, v2) {
		t.Error("Downloaded file is not the same", v, v2)
	}
}

func TestDeepAppendShared(t *testing.T) {
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Error getting user")
	}
	msg := []byte("Huge test")
	msg2 := []byte("123213123")
	msg3 := []byte("123a;lfg03kjsdngew09r sl;gj")
	msg4 := []byte("ads;fwebfb wefowejo3rio3")
	fullMsg := append(msg, msg2...)
	fullMsg = append(fullMsg, msg3...)
	fullMsg = append(fullMsg, msg4...)
	u.StoreFile("Deep Append", msg)
	loaded, err2 := u.LoadFile("Deep Append")
	if err2 != nil || !reflect.DeepEqual(loaded, msg) {
		t.Error("Error in msg1", err2)
	}
	u.AppendFile("Deep Append", msg2)
	u.AppendFile("Deep Append", msg3)
	u.AppendFile("Deep Append", msg4)
	loaded2, err3 := u.LoadFile("Deep Append")
	if err3 != nil || !reflect.DeepEqual(loaded2, fullMsg) {
		t.Error("Did not append multiple times correctly")
	}
	//sharing portion

	u2, err := InitUser("bobbo", "fubar")
	if err != nil {
		t.Error("Failed to create bobbo")
	}
	magic_string, err := u.ShareFile("Deep Append", "bobbo")

	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	errBadMagic := u2.ReceiveFile("Deep Append Alice", "alice", magic_string + "uh")
	if errBadMagic == nil {
		t.Error("Didn't error out with a bad magic string")
	}

	err2 = u2.ReceiveFile("Deep Append Alice", "alice", magic_string)
	if err2 != nil {
		t.Error("Failed to receive the share message", err2)
	}

	v2, err := u2.LoadFile("Deep Append Alice")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(loaded2, v2) {
		t.Error("Shared file is not the same", loaded2, v2)
	}
}

func TestShare(t *testing.T) {
	userlib.SetDebugStatus(true)
	u, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to reload user", err)
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	var v, v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
	}
	userlib.SetDebugStatus(false)
}

func TestRileyStoreFunc(t *testing.T) {
	// t.Log("Riley's Test")

	// You may want to turn it off someday
	userlib.SetDebugStatus(true)

	//create data to be stored and user
	v := []byte("This is a test")
	// t.Log("Data Sent: ", v)
	u, _ := InitUser("alice", "fubar")
	u.StoreFile("file1", v)

	//retrieve FileTable with given user
	fileTableBytes, _ := userlib.DatastoreGet(u.FileTable)
	decryptedFileTable, _ := AuthenticatedDecryption(u.FileTableKey, fileTableBytes)
	var fileTable *FileTable
	_ = json.Unmarshal(decryptedFileTable, &fileTable)
	//retrieve File with given filetable uuid and filekey
	fileTableUUIDAndFileKey := fileTable.FileNameMapping["file1"]
	fileBytes, _ := userlib.DatastoreGet(fileTableUUIDAndFileKey.FileLoc)
	decryptedFile,_ := AuthenticatedDecryption(fileTableUUIDAndFileKey.FileKey, fileBytes)
	var file *File
	_ = json.Unmarshal(decryptedFile, &file)
	//retrieve fileCompartment at index 0 with given File uuid and filekey
	fileUUIDAndFileKey := file.FileIndexMapping[0]
	fileCompartmentBytes, _ := userlib.DatastoreGet(fileUUIDAndFileKey.FileLoc)
	decryptedFileCompartment, _ := AuthenticatedDecryption(fileUUIDAndFileKey.FileKey, fileCompartmentBytes)
	var fileCompartment *FileCompartment
	_ = json.Unmarshal(decryptedFileCompartment, &fileCompartment)
	if reflect.DeepEqual(fileCompartment.Data, fileCompartment.Data) == false {
		t.Error("Failed to properly store data.")
		}
	// t.Log("User fileCompartment ",fileCompartment)
	userlib.SetDebugStatus(false)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

func TestRevoke(t *testing.T) {
	userlib.SetDebugStatus(true)
	u, err := InitUser("Riley", "superDuper")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
	}
	u2, err2 := InitUser("Mallory", "thiefer")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
	}

	v := []byte("This is a test")
	// t.Log("File stored: ", v)
	u.StoreFile("file1", v)
	u, err = GetUser("Riley", "superduper")
	u, err = GetUser("Riley", "superDuper")
	loadedFile, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err, loadedFile)
	}
	// t.Log("File loaded: ", loadedFile)

	var magic_string string
	magic_string, err = u.ShareFile("file1", "Mallory")
	if err != nil {
		t.Error("Failed to share the a file", err)
	}
	err = u2.ReceiveFile("file1", "Riley", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
	}

	err = u.RevokeFile("file1")
	if err != nil {
		t.Error("Failed to revoke the file: ", err)
	}
	// t.Log("Revoked worked?")
	loadedFile, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("u2 loaded the file when they shouldn't have: ", err)
	}
	loadedFile, err = u.LoadFile("file1")
	if err != nil {
		t.Error("u Failed to load the file: ", err)
	}

	userlib.SetDebugStatus(false)
}
func TestLogin(t *testing.T) {
	// t.Log("BadUserNameOrPassword Test")
	u, err := InitUser("alice2.0", "fubar")
	if err != nil {
		t.Error("Error in Bad Password", err)
	}
	u2, err := GetUser("alice2.0", "fubarr")
	if err == nil {
		t.Error("Got access with bad password for user u2", u2)
	}
	u3, err := GetUser("alice2.00", "fubar")
	if err == nil {
		t.Error("Got user from nonexistent username", u3)
	}
	u4, err := GetUser("alice2.0", "fubar")
	if err != nil || u4.Username != u.Username {
		t.Error("Error in loging back in", err)
	}
	if u.Username == u2.Username || u.Username == u3.Username {
		t.Error("Got the same user from bad login")
	}
}
