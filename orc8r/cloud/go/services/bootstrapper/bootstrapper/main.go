/*
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"crypto/rsa"
	"flag"

	"magma/orc8r/cloud/go/blobstore"
	"magma/orc8r/cloud/go/services/bootstrapper/servicers/registration"
	"magma/orc8r/cloud/go/sqorc"
	storage2 "magma/orc8r/cloud/go/storage"

	"github.com/golang/glog"

	"magma/orc8r/cloud/go/orc8r"
	"magma/orc8r/cloud/go/service"
	"magma/orc8r/cloud/go/services/bootstrapper"
	"magma/orc8r/cloud/go/services/bootstrapper/servicers"
	"magma/orc8r/lib/go/protos"
	"magma/orc8r/lib/go/security/key"
)

var (
	keyFilepath = flag.String("cak", "bootstrapper.key.pem", "Bootstrapper's Private Key file")
)

func main() {
	srv, err := service.NewOrchestratorService(orc8r.ModuleName, bootstrapper.ServiceName)
	if err != nil {
		glog.Fatalf("Error creating service: %+v", err)
	}

	bs := createBootstrapperServicer()
	crs, rs := createRegistrationServicers()

	protos.RegisterBootstrapperServer(srv.GrpcServer, bs)
	protos.RegisterCloudRegistrationServer(srv.GrpcServer, crs)
	protos.RegisterRegistrationServer(srv.GrpcServer, rs)

	err = srv.Run()
	if err != nil {
		glog.Fatalf("Error running service: %+v", err)
	}
}

func createBootstrapperServicer() (*servicers.BootstrapperServer) {
	key, err := key.ReadKey(*keyFilepath)
	if err != nil {
		glog.Fatalf("Error reading bootstrapper private key: %+v", err)
	}
	rsaPrivateKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		glog.Fatalf("Error coercing bootstrapper private key to RSA private key; actual type: %T", key)
	}

	servicer, err := servicers.NewBootstrapperServer(rsaPrivateKey)
	if err != nil {
		glog.Fatalf("Error creating bootstrapper servicer: %+v", err)
	}
	return servicer
}

func createRegistrationServicers() (protos.CloudRegistrationServer, protos.RegistrationServer) {
	db, err := sqorc.Open(storage2.GetSQLDriver(), storage2.GetDatabaseSource())
	if err != nil {
		glog.Fatalf("Failed to connect to database: %s", err)
	}
	factory := blobstore.NewSQLStoreFactory(bootstrapper.DBTableName, db, sqorc.GetSqlBuilder())
	err = factory.InitializeFactory()
	if err != nil {
		glog.Fatalf("Error initializing tenant database: %s", err)
	}
	store := registration.NewBlobstoreStore(factory)

	crs, err := registration.NewCloudRegistrationServicer(store)
	if err != nil {
		glog.Fatalf("Error creating cloud registration servicer: %s", err)
	}

	rs, err := registration.NewRegistrationServer(store)
	if err != nil {
		glog.Fatalf("Error creating registration servicer: %s", err)
	}

	return crs, rs
}
