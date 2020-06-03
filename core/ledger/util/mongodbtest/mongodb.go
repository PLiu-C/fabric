/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package mongodbtest

import (
	"fmt"
	"os"

	"github.com/hyperledger/fabric/integration/runner"
)

// MongoDBSetup setup external couchDB resource.
func MongoDBSetup( /*binds []string*/ ) (addr string, cleanup func()) {
	// check if couchDB is being started externally.
	externalMongo, set := os.LookupEnv("MONGODB_ADDR")
	if set {
		return externalMongo, func() {}
	}

	mongoDB := &runner.MongoDB{}
	//couchDB.Binds = binds

	if err := mongoDB.Start(); err != nil {
		err := fmt.Errorf("failed to start mongoDB: %s", err)
		panic(err)
	}
	return mongoDB.Address(), func() { mongoDB.Stop() }
}
