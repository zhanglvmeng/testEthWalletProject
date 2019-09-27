package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/meitu/go-ethereum/crypto/sha3"
	"io/ioutil"
	"log"
	"math/big"
	"strings"
	"time"
)

/**
	创建
 */
func createKs() {
	// 注意路径要写到 keystore 这一层，而不是其上一层。 比如应该这样 /Users/zhangpeng/ethData/keystore
	ks := keystore.NewKeyStore("/Users/zhangpeng/ethData", keystore.StandardScryptN, keystore.StandardScryptP)
	password := "root"
	account, err := ks.NewAccount(password)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(account.Address.Hex()) // 0xfDCbC8E2e02638bd6BdfdD3d90078ac052a5Ff71
}

func importKs() {
	// 要引入的keystore的json文件. 这个demo中随便写了一个key文件地址。具体引入时写真实的地址即可。
	file := "/Users/zhangpeng/ethData/UTC--2019-09-17T09-43-53.829296000Z--24aa682c19454e8346d692421e9e1fb305936599"
	// keydir 同样要写入到keystore这一层
	ks := keystore.NewKeyStore("/Users/zhangpeng/ethData/keystore", keystore.StandardScryptN, keystore.StandardScryptP)

	jsonBytes, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	password := "root"
	//ks.Accounts()
	account, err := ks.Import(jsonBytes, password, password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(account.Address.Hex()) // 0xfDCbC8E2e02638bd6BdfdD3d90078ac052a5Ff71

	// 删掉file 。 可以先暂时不删，注释掉下面的代码
	//if err := os.Remove(file); err != nil {
	//	log.Fatal(err)
	//}
}

/**
	获取client
 */
func getRpcClient() (*rpc.Client, error) {
	client, err := rpc.Dial("http://localhost:8545")
	return client, err
}

/**
	获取所有账户
 */
func getAccounts() ([]string, error) {
	var account []string
	client, err := getRpcClient()
	defer client.Close()

	if err != nil {
		fmt.Println("rpc.Dial err", err)
		return []string{}, err
	}
	err = client.Call(&account, "eth_accounts")
	if err != nil {
		fmt.Println("client call error", err)
		return []string{}, err
	}
	fmt.Println("account的数量: ", len(account))
	return account, nil
}

/**
	生成原生新钱包
 */
func generateNewRawWallet()  {
	// 私钥
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		log.Fatal(err)
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	fmt.Println("私钥：==========")
	fmt.Println(hexutil.Encode(privateKeyBytes)[2:]) // 0xfad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19

	// 公钥
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
	}

	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	fmt.Println("公钥：==========")
	fmt.Println(hexutil.Encode(publicKeyBytes)[4:]) // 0x049a7df67f79246283fdc93af76d4f8cdd62c4886e8cd870944e817dd0b97934fdd7719d0810951e03418205868a5c1b40b192451367f28e0088dd75e15de40c05

	// 地址
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	fmt.Println("地址：==========")
	fmt.Println(address) // 0x96216849c49358B10257cb55b28eA603c874b05E

	hash := sha3.NewKeccak256()
	hash.Write(publicKeyBytes[1:])
	fmt.Println(hexutil.Encode(hash.Sum(nil)[12:]))

}

func getBlockInfo()  {
	client, err := ethclient.Dial("http://localhost:8545") // 本地
	//client, err := ethclient.Dial("https://mainnet.infura.io") // 主网地址
	if err != nil {
		log.Fatal(err)
	}
	header, err := client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("header number is ", header.Number.String()) // 5671744

	fmt.Println(header.Number.String()) // 5671744

	blockNumber := big.NewInt(620)
	block, err := client.BlockByNumber(context.Background(), blockNumber)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("block 信息")
	fmt.Println(block.Number().Uint64())     // 5671744
	fmt.Println(block.Time())       // 1527211625
	fmt.Println(block.Difficulty().Uint64()) // 3217000136609065
	fmt.Println(block.Hash().Hex())          // 0x9e8751ebb5069389b855bba72d94902cc385042661498a415979b7b6ee9ba4b9
	fmt.Println("block 中交易的数目")
	fmt.Println(len(block.Transactions()))   // 144
	count, err := client.TransactionCount(context.Background(), block.Hash())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(count) // 144

	// 获取交易的详细信息
	fmt.Println("打印block中交易的详细信息")
	for i, tx := range block.Transactions() {
		fmt.Println("交易  ", i, " --- begin")
		fmt.Println(tx.Hash().Hex())        // 0x5d49fcaa394c97ec8a9c3e7bd9e8388d420fb050a52083ca52ff24b3b65bc9c2
		fmt.Println(tx.Value().String())    // 10000000000000000
		fmt.Println(tx.Gas())               // 105000
		fmt.Println(tx.GasPrice().Uint64()) // 102000000000
		fmt.Println(tx.Nonce())             // 110644
		fmt.Println(tx.Data())              // []
		fmt.Println(tx.To().Hex())          // 0x55fE59D8Ad77035154dDd0AD0388D09Dd4047A8e

		chainID, err := client.NetworkID(context.Background())
		fmt.Println("chainId is ", chainID)
		if err != nil {
			log.Fatal(err)
		}

		// 读取receipt 信息
		if msg, err := tx.AsMessage(types.NewEIP155Signer(chainID)); err == nil {
			fmt.Println(msg.From().Hex()) // 0x0fD081e3Bb178dc45c0cb23202069ddA57064258
		}

		receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println(receipt.Status) // 1
		fmt.Println("交易  ", i, " --- end")

	}


}

func getPrivateKeyByKeystore(keystoreDir string, signPassword string) *ecdsa.PrivateKey {
	// Open the account key file
	keyJson, readErr := ioutil.ReadFile(keystoreDir)
	if readErr != nil {
		fmt.Println("key json read error:")
		panic(readErr)
	}

	// Get the private key
	keyWrapper, keyErr := keystore.DecryptKey(keyJson, signPassword)
	if keyErr != nil {
		fmt.Println("key decrypt error:")
		panic(keyErr)
	}
	fmt.Printf("key extracted: addr=%s", keyWrapper.Address.String())

	privateKey := keyWrapper.PrivateKey
	return privateKey
}
/*
	发送交易
	参数： 	私钥
			接受者的地址（十六进制）
*/
func sendTransaction(keystoreDir, signPassword, toAddressRaw string, sendValue int64) bool {
	// TODO 目前看 sendValue 不能超过 10 eth, 这是为什么啊？？？？？不会这么小吧？？？
	client, err := ethclient.Dial("http://localhost:8545")
	if err != nil {
		log.Fatal(err)
		return false
	}
	// 1 利用keystore文件生成 私钥。 signPassword 是用户创建钱包时设置的password
	privateKey := getPrivateKeyByKeystore(keystoreDir, signPassword)

	// 2 利用私钥生成公钥，进而生成地址。
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatal("error casting public key to ECDSA")
		return false
	}

	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	// 3 交易需要的nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatal(err)
		return false
	}
	// 4 交易金额
	value := big.NewInt(1000000000000000000 * sendValue) // in wei (1 eth)
	// 5 交易最大的gas 数量。固定的操作，在以太坊中花费也是固定的。
	gasLimit := uint64(21000)                // in units
	// 6 gasPrice 每个gas的价格，单位为wei.
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatal(err)
		return false
	}

	toAddress := common.HexToAddress(toAddressRaw)
	var data []byte
	// 封装交易
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)

	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatal(err)
		return false
	}

	// 签名交易
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatal(err)
		return false
	}

	// 广播到全网
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatal(err)
		return false
	}

	fmt.Printf("tx sent: %s", signedTx.Hash().Hex())
	return true
}

func createFilter() ([]string, error) {
	var account []string
	client, err := getRpcClient()
	defer client.Close()

	if err != nil {
		fmt.Println("rpc.Dial err", err)
		return []string{}, err
	}
	err = client.Call(&account, "eth_newFilter", )
	if err != nil {
		fmt.Println("client call error", err)
		return []string{}, err
	}
	fmt.Println("account的数量: ", len(account))
	return account, nil
}

// 接收最新的区块信息
func getTheLastestBlock()  {
	client, err := ethclient.Dial("wss://ropsten.infura.io/ws")
	// 需要公链开启ws。 启动时 加 --ws --wsaddr localhost --wsport 8546  参数
	//client, err := ethclient.Dial("ws://localhost:8546/ws")
	if err != nil {
		log.Fatal(err)
	}

	headers := make(chan *types.Header)
	sub, err := client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatal(err)
	}

	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			fmt.Println("区块来了~ hash: ")
			fmt.Println(header.Hash().Hex()) // 0xbc10defa8dda384c96a17640d84de5578804945d347072e091b4e5f390ddea7f

			block, err := client.BlockByHash(context.Background(), header.Hash())
			if err != nil {
				log.Fatal(err)
			}

			//fmt.Println(block.Hash().Hex())        // 0xbc10defa8dda384c96a17640d84de5578804945d347072e091b4e5f390ddea7f
			fmt.Println("区块编号：", block.Number().Uint64())   // 3477413
			//fmt.Println(block.Time())     // 1529525947
			//fmt.Println(block.Nonce())             // 130524141876765836
			transLen := len(block.Transactions())
			fmt.Println("区块中包含的交易数量：", transLen) // 7
			// 遍历交易
			fmt.Println("开始遍历transaction.........")
			txCount := 0
			for _, trans := range block.Transactions() {
				fmt.Println("遍历第", txCount, "个交易===================================")
				fmt.Println("交易的hash值：", hex.EncodeToString(trans.Hash().Bytes()))
				// 获取收据信息
				trans.RawSignatureValues()
				receipt, err := client.TransactionReceipt(context.Background(), trans.Hash())
				if err != nil {
					fmt.Println("从交易", hex.EncodeToString(trans.Hash().Bytes()), "获取收据 失败  :", err)
					continue
				}
				//fmt.Println("================收据信息==================")
				//receiptJson, err := json.Marshal(receipt)
				//if err == nil {
				//	fmt.Println(string(receiptJson))
				//} else {
				//	fmt.Println("收据转json失败, error", err)
				//	txCount++
				//	continue
				//}

				receiptLog := (*receipt).Logs
				if len(receiptLog) == 0 {
					txCount++
					fmt.Println("收据信息中没有Log, 跳过这次的交易。。。。。")
					continue
				}

				//// 打印log信息
				//receiptLogJson, err := json.Marshal(receiptLog)
				//if err != nil {
				//	txCount++
				//	fmt.Println("收据信息中Log格式有问题, 跳过这次的交易。。。。。")
				//	continue
				//} else {
				//	fmt.Println("收据的日志为 ", string(receiptLogJson))
				//}
				for _, log := range receiptLog {
					contractAddr := (*log).Address
					fmt.Println("合约地址: ", contractAddr.String())
					topics := log.Topics
					topicLen := len(topics)
					if topicLen == 3 {
						if strings.Compare(topics[0].String(), "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef") == 0 {
							fmt.Println("keccak: ", topics[0].String())
							fmt.Println("from: ", topics[1].String())
							fmt.Println("to:", topics[2].String())
						} else {
							fmt.Println("topic的长度为3 ，但是不是ERC20交易，跳过。。。。。。")
						}
					} else if  topicLen == 1 || topicLen == 2 {
						fmt.Println("Topic 数量为", topicLen, " 不足3个，跳过。。。。。")
						fmt.Println("不合法： 第一个字段是", topics[0].String())
					}
				}
				time.Sleep(time.Millisecond * 50)
				txCount++
				// TODO 先暂停一下，调试OK 再放开。
				//break
			}


		}
	}
}

func main() {
	fmt.Println("hello23")
	//getAccounts()
	// 0x2F3cC43cE8a6d1c0dEbFa0129c7459C4d3df8b84
	//generateNewRawWallet()
	//createKs()
	//importKs()
	//getBlockInfo()
	//sendTransaction("/Users/zhangpeng/ethData/keystore/UTC--2019-09-17T09-45-19.896945000Z--24aa682c19454e8346d692421e9e1fb305936599", "root", "0x33c65279e413e401ff56471a4714e9eb8fd3fc72", 3)
	getTheLastestBlock()

}