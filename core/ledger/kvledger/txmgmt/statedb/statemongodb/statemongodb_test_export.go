/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package statemongodb

import (
	"testing"
	"time"

	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/stretchr/testify/assert"

	"github.com/hyperledger/fabric/core/ledger/kvledger/txmgmt/statedb"
	"github.com/hyperledger/fabric/core/ledger/util/mongodb"
)

// TestVDBEnv provides a mongodb backed versioned db for testing
type testVDBEnv struct {
	t              testing.TB
	mongoAddress   string
	DBProvider     statedb.VersionedDBProvider
	config         *mongodb.Config
	cleanupMongoDB func()
}

func (env *testVDBEnv) init(t testing.TB) {
	t.Logf("Initializing TestVDBEnv")

	env.startExternalResource()

	config := &mongodb.Config{
		Address:             env.mongoAddress,
		Username:            "",
		Password:            "",
		AuthSource:          "",
		DatabaseName:        "statedb",
		MaxRetries:          3,
		MaxRetriesOnStartup: 10,
		RequestTimeout:      35 * time.Second,
		QueryLimit:          1000,
		MaxBatchUpdateSize:  1000,
	}
	dbProvider, err := NewVersionedDBProvider(config, &disabled.Provider{})
	if err != nil {
		t.Fatalf("Error creating MongoDB Provider: %s", err)
	}

	env.t = t
	env.DBProvider = dbProvider
	env.config = config
}

func (env *testVDBEnv) startExternalResource() {
	if env.mongoAddress == "" {
		env.mongoAddress, env.cleanupMongoDB = MongoDBSetup()
	}
}

// stopExternalResource stops external MongoDB resources.
func (env *testVDBEnv) stopExternalResource() {
	if env.mongoAddress != "" {
		env.cleanupMongoDB()
	}
}

// Cleanup drops the test mongo databases and closes the db provider
func (env *testVDBEnv) cleanup() {
	env.t.Logf("Cleaningup TestVDBEnv")
	CleanupDB(env.t, env.DBProvider.(*VersionedDBProvider))
	env.DBProvider.Close()
}

func CleanupDB(t testing.TB, dbProvider statedb.VersionedDBProvider) {
	mongodbProvider, _ := dbProvider.(*VersionedDBProvider)
	for _, v := range mongodbProvider.databases {
		if err := v.metadataDB.DropCollection(); err != nil {
			assert.Failf(t, "DropCollection %s fails. err: %v", v.metadataDB.CollectionName, err)
		}

		for _, db := range v.namespaceDBs {
			if err := db.DropCollection(); err != nil {
				assert.Failf(t, "DropCollection %s fails. err: %v", db.CollectionName, err)
			}
		}
	}
}
