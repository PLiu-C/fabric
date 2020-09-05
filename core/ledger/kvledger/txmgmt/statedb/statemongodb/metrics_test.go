///*
//Copyright IBM Corp. All Rights Reserved.
//SPDX-License-Identifier: Apache-2.0
//*/
//
package statemongodb

//
import (
	"testing"

	"github.com/hyperledger/fabric/common/metrics/disabled"
	"github.com/hyperledger/fabric/common/metrics/metricsfakes"
	. "github.com/onsi/gomega"
)

func TestAPIProcessTimeMetric(t *testing.T) {
	collection := "testapi"
	gt := NewGomegaWithT(t)
	fakeHistogram := &metricsfakes.Histogram{}
	fakeHistogram.WithReturns(fakeHistogram)

	// create a new mongo instance
	config := testConfig()
	config.MaxRetries = 0
	mongoInstance, err := CreateMongoInstance(config, &disabled.Provider{})
	gt.Expect(err).NotTo(HaveOccurred(), "Error when trying to create mongo instance")

	mongoInstance.stats = &stats{
		apiProcessingTime: fakeHistogram,
	}

	db := MongoDatabase{MongoInstance: mongoInstance, DatabaseName: mongoInstance.conf.DatabaseName, CollectionName: collection}
	db.GetDatabaseInfo()
	gt.Expect(fakeHistogram.ObserveCallCount()).To(Equal(1))
	gt.Expect(fakeHistogram.ObserveArgsForCall(0)).NotTo(BeZero())
	gt.Expect(fakeHistogram.WithArgsForCall(0)).To(Equal([]string{
		"collection", "testapi",
		"function_name", "GetDatabaseInfo",
	}))
}
