package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/internal/fileutils"
	"github.com/ethereum/go-ethereum/mycelo/config"
	"github.com/ethereum/go-ethereum/p2p/enode"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
)

type NodeConfig struct {
	GethPath      string
	ChainID       *big.Int
	Number        int
	Account       config.Account
	OtherAccounts []config.Account
	Datadir       string
}

func (nc *NodeConfig) RPCPort() int64 {
	return int64(8545 + nc.Number)
}

func (nc *NodeConfig) NodePort() int64 {
	return int64(30303 + nc.Number)
}

type Node struct {
	*NodeConfig
}

func NewNode(cfg *NodeConfig) *Node {
	return &Node{
		NodeConfig: cfg,
	}
}

func (n *Node) runSync(args ...string) ([]byte, error) {
	args = append([]string{"--datadir", n.Datadir}, args...)
	cmd := exec.Command(n.GethPath, args...)
	return cmd.CombinedOutput()
}

func (n *Node) pwdFile() string         { return path.Join(n.Datadir, "password") }
func (n *Node) logFile() string         { return path.Join(n.Datadir, "geth.log") }
func (n *Node) keyFile() string         { return path.Join(n.Datadir, "celo/nodekey") }
func (n *Node) staticNodesFile() string { return path.Join(n.Datadir, "/celo/static-nodes.json") }

func (n *Node) ImportKeystoreAccounts(keystorePaths ...string) error {
	for _, keystorePath := range keystorePaths {
		_, name := path.Split(keystorePath)
		if _, err := fileutils.Copy(keystorePath, path.Join(n.Datadir, "keystore", name)); err != nil {
			return err
		}
	}
	return nil
}

func (n *Node) Init(GenesisJSON string) error {
	if fileutils.FileExists(n.Datadir) {
		os.RemoveAll(n.Datadir)
	}
	os.MkdirAll(n.Datadir, os.ModePerm)

	// Write password file
	if err := ioutil.WriteFile(n.pwdFile(), []byte{}, os.ModePerm); err != nil {
		return err
	}

	// Run geth init
	if out, err := n.runSync("init", GenesisJSON); err != nil {
		os.Stderr.Write(out)
		return err
	}

	// Generate nodekey file (enode private key)
	if err := n.generateNodeKey(); err != nil {
		return err
	}

	// Add Accounts
	ks := keystore.NewKeyStore(path.Join(n.Datadir, "keystore"), keystore.LightScryptN, keystore.LightScryptP)
	if _, err := ks.ImportECDSA(n.Account.PrivateKey, ""); err != nil {
		return err
	}
	for _, acc := range n.OtherAccounts {
		if _, err := ks.ImportECDSA(acc.PrivateKey, ""); err != nil {
			return err
		}
	}

	return nil
}

func (n *Node) generateNodeKey() error {
	nodeKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}
	if err = crypto.SaveECDSA(n.keyFile(), nodeKey); err != nil {
		return err
	}
	return nil
}

func (n *Node) SetStaticNodes(enodeUrls ...string) error {
	var staticNodesRaw []byte
	var err error

	if staticNodesRaw, err = json.Marshal(enodeUrls); err != nil {
		return fmt.Errorf("Can't serialize static nodes: %w", err)
	}
	//nolint:gosec
	if err = ioutil.WriteFile(n.staticNodesFile(), staticNodesRaw, 0644); err != nil {
		return fmt.Errorf("Can't serialize static nodes: %w", err)
	}

	return nil
}

func (n *Node) EnodeURL() (string, error) {
	nodekey, err := crypto.LoadECDSA(n.keyFile())
	if err != nil {
		return "", err
	}
	ip := net.IP{127, 0, 0, 1}
	en := enode.NewV4(&nodekey.PublicKey, ip, int(n.NodePort()), int(n.NodePort()))
	return en.URLv4(), nil
}

func (n *Node) AccountAddresses() []common.Address {
	ks := keystore.NewKeyStore(path.Join(n.Datadir, "keystore"), keystore.LightScryptN, keystore.LightScryptP)
	addresses := make([]common.Address, 0)
	for _, acc := range ks.Accounts() {
		addresses = append(addresses, acc.Address)
	}
	return addresses
}

func (n *Node) Run(ctx context.Context) error {

	var addressToUnlock string
	for _, addr := range n.AccountAddresses() {
		addressToUnlock += "," + addr.Hex()
	}

	args := []string{
		"--datadir", n.Datadir,
		"--verbosity", "4",
		"--networkid", n.ChainID.String(),
		"--syncmode", "full",
		"--mine",
		"--allow-insecure-unlock",
		"--nat", "extip:127.0.0.1",
		"--port", strconv.FormatInt(n.NodePort(), 10),
		"--rpc",
		"--rpcaddr", "127.0.0.1",
		"--rpcport", strconv.FormatInt(n.RPCPort(), 10),
		"--rpcapi", "eth,net,web3,debug,admin,personal",
		// "--nodiscover", "--nousb ",
		"--etherbase", n.Account.Address.Hex(),
		"--unlock", addressToUnlock,
		"--password", n.pwdFile(),
	}
	cmd := exec.Command(n.GethPath, args...)

	log.Println(n.GethPath, strings.Join(args, " "))

	logfile, err := os.OpenFile(n.logFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer logfile.Close()
	cmd.Stderr = logfile
	// cmd.Stdout = os.Stdout
	// cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return err
	}

	// rpc, err := rpc.Dial(fmt.Sprintf("http://localhost:%d", n.RPCPort()))
	// if err != nil {
	// 	return err
	// }
	// rpc.CallContext(ctx, nil, "personal_unlock", )

	go func() {
		<-ctx.Done()
		if err := cmd.Process.Kill(); err != nil {
			log.Fatal("Failed to kill geth cmd")
		}
	}()

	return cmd.Wait()
}