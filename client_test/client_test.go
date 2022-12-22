package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var jesus *client.User
	var draymond *client.User
	var lilpump *client.User
	var peyrin *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var lilpump *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var jesusPhone *client.User
	var jesusLaptop *client.User
	var jesusDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	jesusFile := "jesusFile.txt"
	draymondFile := "draymondFile.txt"
	peyrinFile := "peyrinFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	lilpumpFile := "lilpumpFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user jesus.")
			jesusLaptop, err = client.GetUser("jesus", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = jesus.AppendToFile(jesusFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = jesus.AppendToFile(jesusFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := jesus.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users jesus (jesusDesktop) and draymond.")
			jesusDesktop, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of jesus - jesusLaptop")
			jesusLaptop, err = client.GetUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop storing file %s with content: %s", jesusFile, contentOne)
			err = jesusDesktop.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusLaptop creating invite for draymond.")
			invite, err := jesusLaptop.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			userlib.DebugMsg("draymond accepting invite from jesus under filename %s.", draymondFile)
			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("draymond appending to file %s, content: %s", draymondFile, contentTwo)
			err = draymond.AppendToFile(draymondFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop appending to file %s, content: %s", jesusFile, contentThree)
			err = jesusDesktop.AppendToFile(jesusFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that jesusDesktop sees expected file data.")
			data, err := jesusDesktop.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that jesusLaptop sees expected file data.")
			data, err = jesusLaptop.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that draymond sees expected file data.")
			data, err = draymond.LoadFile(draymondFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of jesus - jesusPhone.")
			jesusPhone, err = client.GetUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that jesusPhone sees jesus's changes.")
			data, err = jesusPhone.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users jesus, draymond, and Charlie.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			peyrin, err = client.InitUser("peyrin", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus storing file %s with content: %s", jesusFile, contentOne)
			jesus.StoreFile(jesusFile, []byte(contentOne))

			userlib.DebugMsg("jesus creating invite for draymond for file %s, and draymond accepting invite under name %s.", jesusFile, draymondFile)

			invite, err := jesus.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that jesus can still load the file.")
			data, err := jesus.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that draymond can load the file.")
			data, err = draymond.LoadFile(draymondFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("draymond creating invite for peyrin for file %s, and Charlie accepting invite under name %s.", draymondFile, peyrinFile)
			invite, err = draymond.CreateInvitation(draymondFile, "peyrin")
			Expect(err).To(BeNil())

			err = peyrin.AcceptInvitation("draymond", invite, peyrinFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that peyrin can load the file.")
			data, err = peyrin.LoadFile(peyrinFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("jesus revoking draymond's access from %s.", jesusFile)
			err = jesus.RevokeAccess(jesusFile, "draymond")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that jesus can still load the file.")
			data, err = jesus.LoadFile(jesusFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that draymond/peyrin lost access to the file.")
			_, err = draymond.LoadFile(draymondFile)
			Expect(err).ToNot(BeNil())

			_, err = peyrin.LoadFile(peyrinFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = draymond.AppendToFile(draymondFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = peyrin.AppendToFile(peyrinFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Empty Username Test", func() {
			userlib.DebugMsg("Initializing user")
			emptyUser, err := client.InitUser(emptyString, defaultPassword)
			print(emptyUser)
			Expect(err).ToNot(BeNil())
		})

		Specify("File not shared w recipient", func() {

			userlib.DebugMsg("Initializing user draymond.")
			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus storing file %s with content: %s", jesusFile, contentOne)
			jesus.StoreFile(jesusFile, []byte(contentOne))

			userlib.DebugMsg("jesus creating invite for draymond for file %s, and draymond accepting invite under name %s.", jesusFile, draymondFile)
			invite, err := jesus.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus revoking draymond's access from %s.", jesusFile)
			err = jesus.RevokeAccess(jesusFile, "peyrin")
			Expect(err).ToNot(BeNil())

		})

		Specify("No user init for username", func() {
			userlib.DebugMsg("Getting user jesus.")
			jesusLaptop, err = client.GetUser("jesus", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("See if attacker changed invitation.", func() {

			userlib.DebugMsg("Initializing users jesus (jesusDesktop), draymond.")

			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			jesusDesktop, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of jesus - jesusLaptop")
			jesusLaptop, err = client.GetUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop storing file %s with content: %s", jesusFile, contentOne)
			err = jesusDesktop.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusLaptop creating invite for draymond.")
			invite, err := jesusLaptop.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Changing invitation struct in datastore")
			userlib.DatastoreSet(invite, []byte("ABC."))

			userlib.DebugMsg("draymond can't accept invitation because it isnt the same")
			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).ToNot(BeNil())

			println()
		})

		Specify("All values changed", func() {
			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Change all values in DS")
			var datastore = userlib.DatastoreGetMap()
			userlib.DebugMsg("Change DS values.")
			for key, _ := range datastore {
				datastore[key] = userlib.RandomBytes(16)
			}

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = jesus.AppendToFile(jesusFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

		})

		Specify("Filename doesn't exist", func() {
			userlib.DebugMsg("Initializing user lilpump.")
			lilpump, err = client.InitUser("lilpump", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = lilpump.StoreFile(lilpumpFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file")
			_, err := lilpump.LoadFile(jesusFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Password empty", func() {
			userlib.DebugMsg("Initializing user jesus.")
			_, err := client.InitUser("jesus", "")
			Expect(err).To(BeNil())

		})

		Specify("revoke access on different thread", func() {

			userlib.DebugMsg("Initialize users jesus draymond and peyrin")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			peyrin, err = client.InitUser("peyrin", defaultPassword)
			Expect(err).To(BeNil())

			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			lilpump, err = client.InitUser("lilpump", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus stores file")
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus creates invite for peyrin")
			invite2, err := jesus.CreateInvitation(jesusFile, "peyrin")
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus creates invite for draymond")
			invite, err := jesus.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			userlib.DebugMsg("peyrin accepts invite from jesus")
			err = peyrin.AcceptInvitation("jesus", invite2, peyrinFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("draymond accepts invite from jesus")
			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("draymond creates invite for lilpump ")
			invite3, err := draymond.CreateInvitation(draymondFile, "lilpump")
			Expect(err).To(BeNil())

			userlib.DebugMsg("lilpump accepts invite from draymond")
			err = lilpump.AcceptInvitation("draymond", invite3, lilpumpFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus revokes access from peyrin")
			err = jesus.RevokeAccess(jesusFile, "peyrin")
			Expect(err).To(BeNil())

			userlib.DebugMsg("lilpump should still be able to access file")
			_, err3 := lilpump.LoadFile(lilpumpFile)
			Expect(err3).To(BeNil())

			userlib.DebugMsg("draymond should still be able to access file")
			_, err2 := draymond.LoadFile(draymondFile)
			Expect(err2).To(BeNil())

		})

		Specify("Malicious action - every value has been changed", func() {

			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			invite, err := jesus.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Change DS values")
			var datastore = userlib.DatastoreGetMap()
			userlib.DebugMsg("Change DS values.")
			for key, _ := range datastore {
				datastore[key] = userlib.RandomBytes(16)
			}

			userlib.DebugMsg("jesus revoking draymond's access from %s.", jesusFile)
			err = jesus.RevokeAccess(jesusFile, "draymond")
			Expect(err).ToNot(BeNil())

		})

		Specify("Load/Edit file from different sessions", func() {
			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = jesus.AppendToFile(jesusFile, []byte(contentThree))
			Expect(err).To(BeNil())
		})

		Specify("Filename doesn't exist", func() {
			userlib.DebugMsg("Initializing user lilpump.")
			lilpump, err = client.InitUser("lilpump", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentTwo)
			err = lilpump.StoreFile(lilpumpFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = lilpump.AppendToFile(jesusFile, []byte(contentThree))
			Expect(err).ToNot(BeNil())

		})

		Specify("Invalid user credentials", func() {
			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user jesus.")
			jesus, err = client.GetUser("jesus", "badpwd")
			Expect(err).ToNot(BeNil())

		})

		Specify("Duplicate Username test", func() {
			userlib.DebugMsg("Initializing user jesus.")
			_, err := client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user with duplicate name should error.")
			_, err2 := client.InitUser("jesus", defaultPassword)
			Expect(err2).ToNot(BeNil())

		})

		Specify("Given filename doesn't exist", func() {

			userlib.DebugMsg("Initializing user draymond.")
			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus storing file %s with content: %s", jesusFile, contentOne)
			jesus.StoreFile(jesusFile, []byte(contentOne))

			userlib.DebugMsg("jesus creating invite for draymond for file %s, and draymond accepting invite under name %s.", jesusFile, draymondFile)
			invite, err := jesus.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesus revoking draymond's access from %s.", jesusFile)
			err = jesus.RevokeAccess(peyrinFile, "draymond")
			Expect(err).ToNot(BeNil())

		})

		Specify("Tamper with Invitation", func() {
			jesus, _ := client.InitUser("jesus", defaultPassword)
			draymond, _ := client.InitUser("draymond", defaultPassword)

			jesus.StoreFile(jesusFile, []byte(contentOne))
			invite, _ := jesus.CreateInvitation(jesusFile, "draymond")

			datastore := userlib.DatastoreGetMap()
			datastore[invite][5] = 0x70

			err := draymond.AcceptInvitation("jesus", invite, "draymondFile.txt")
			Expect(err).ToNot(BeNil())
		})

		Specify("Share file from different sessions", func() {

			userlib.DebugMsg("Initializing user peyrin")
			peyrin, err = client.InitUser("peyrin", "peyrinPassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus ")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = peyrin.StoreFile(peyrinFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user jesus Desktop.")
			jesusDesktop, err = client.GetUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusLaptop creates an invitation")
			invite, err := peyrin.CreateInvitation(peyrinFile, "jesus")
			Expect(err).To(BeNil())

			err = jesusDesktop.AcceptInvitation("peyrin", invite, "somefile.txt")
			Expect(err).To(BeNil())

		})

		Specify("Filename doesn't exist", func() {

			userlib.DebugMsg("Initializing user draymond", contentOne)
			draymond, err = client.InitUser("draymond", "draymondPassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus (jesusDesktop)")
			jesusDesktop, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesusDesktop.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop creating invite for draymond with bad file")
			_, err := jesusDesktop.CreateInvitation("nonexistentfile.txt", "draymond")
			Expect(err).ToNot(BeNil())
		})

		Specify("Can't access file", func() {

			userlib.DebugMsg("Initializing user draymond.")
			draymond, err = client.InitUser("draymond", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user lilpump.")
			lilpump, err = client.InitUser("lilpump", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = lilpump.StoreFile(lilpumpFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop tries to create an invitation with a file she shouldn't have access to")
			_, err := jesus.CreateInvitation(lilpumpFile, "draymond")
			Expect(err).ToNot(BeNil())

		})

		Specify("File already exists in personal file namespace", func() {

			userlib.DebugMsg("Initializing user draymond")
			draymond, err = client.InitUser("draymond", "draymondPassword")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user jesus (jesusDesktop)")
			jesusLaptop, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data for draymondFile: %s", contentTwo)
			err = draymond.StoreFile(draymondFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data for jesusFile: %s", contentOne)
			err = jesusLaptop.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusLaptop creating invite for draymond.")
			invite, err := jesusLaptop.CreateInvitation(jesusFile, "draymond")
			Expect(err).To(BeNil())

			userlib.DebugMsg("draymond accepting invite from jesus under filename %s.", draymondFile)
			err = draymond.AcceptInvitation("jesus", invite, draymondFile)
			Expect(err).ToNot(BeNil())

		})

		Specify("Given recipientUsername does not exist", func() {

			userlib.DebugMsg("Initializing user jesus.")
			jesus, err = client.InitUser("jesus", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = jesus.StoreFile(jesusFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("jesusDesktop tries to create a file for bad recipient")
			_, err := jesusDesktop.CreateInvitation(jesusFile, "alex")
			Expect(err).ToNot(BeNil())

		})

	})
})
