from web3 import Web3, HTTPProvider
import json
import solcx
import datetime
import os
from eth_account.messages import encode_defunct
version = solcx.install_solc('0.8.9') # 최초 1회에만 사용
'''
2023-05-22 
메타트랜잭션 1.0
메타랜잭션 실행 조건
erc-20 함수 approve를 메타트랜잭션 이용자가 선행작업이 필요함
메타트랜잭션을 사용할 erc20 token contract address 를
addwhite list를 해줘야 이용할수 있는 권한이 생긴다.
'''
###### 공용 함수 영역 #####


def ethereum_connectWeb3(infura_api_key, connect_host=None):

	if connect_host is None:
		infura_url = "http://222.231.30.70:8041"
	elif connect_host == "mainnet":
		infura_url = "https://mainnet.infura.io/v3/"+infura_api_key
	elif connect_host == "goerli":
		infura_url = "https://goerli.infura.io/v3/"+infura_api_key
	elif connect_host == "sepolia":
		infura_url = "https://sepolia.infura.io/v3/"+infura_api_key
	elif connect_host == "gnceth":		#훗날에 바꿔야함 20230109
		infura_url = "http://222.231.30.70:8041"
	else:
		infura_url = "http://localhost:8545"
	web3 = Web3(Web3.HTTPProvider(infura_url))
	print(f"{infura_url} connect is {web3.is_connected()}")
	return web3

def ethereum_check_network(web3):
    check = web3.net.version
    if check == "1":
        network = "mainnet"
    elif check == "5":
        network = "goerli"
    elif check == "11155111":
        network = "sepolia"
    else:
        network = "Unknown"

    return network

def ethereum_etherscan_link(network, contract_address):
    if network == "mainnet":
        url = f"https://etherscan.io/address/{contract_address}"
    elif network == "goerli":
        url = f"https://goerli.etherscan.io/address/{contract_address}"
    else:
        url = "unknown"

    return url
def ethereum_getBalance(web3, account):
	account = web3.to_checksum_address(account)
	balance = web3.from_wei(web3.eth.get_balance(account), 'ether')
	return balance

def ethereum_read_abi(file_name):
	with open(file_name) as f:
		info_json = json.load(f)
	return info_json["abi"]

def ethereum_getContract(web3, contractAddress, contractAbi):
	file = open(contractAbi, 'r', encoding='utf-8')
	contractaddress = web3.to_checksum_address(contractAddress)
	mycontract = web3.eth.contract(abi=file.read(), address=contractaddress)
	return mycontract

def ether_deploy_forward(web3, file_path, address, pk_key):
    address =  web3.to_checksum_address(address)

    res = solcx.compile_files(
        [file_path],
        output_values=["abi", "bin"],
        solc_version="0.8.9"
    )
    abi = res[file_path + ':TokenSender']['abi']
    with open('TokenSenderabi', 'w') as f:
        json.dump(abi, f)

    bytecode = res[file_path + ':TokenSender']['bin']
#    with open('TokenSenderabi','w')as f:
#        json.dump(bytecode,f)
    #exit()
    #gas_price = utill.get_gas_price("average")
    gas_price = web3.eth.gas_price
    mycontract = web3.eth.contract(abi=abi, bytecode=bytecode)
    acct = web3.eth.account.from_key(pk_key)
    nonce = web3.eth.get_transaction_count(address)
    tx = mycontract.constructor().build_transaction(
        {
            "from": address,
            "nonce": nonce,
            "gasPrice": gas_price,

        }
    )
    signed = acct.signTransaction(tx)
    tx_hash = web3.eth.send_raw_transaction(signed.rawTransaction)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return tx_receipt.contractAddress

##### 트랜잭션 영역 #####
# 수수료 소모 #
##############################################


def eth_meta_transfer(web3, mycontract, sender,sender_pk, recipients , amounts, token_contract_add, fee_payer, fee_payer_pk, gas_price):
    '''
    use : metatransaction 선행조건 : token_contract_add에 sender가 approve를 해줘야한다. token_contract_add를 addwhitelist를 meta_contract owner가 등록 해줘야한다.
    pram
    web3 : 체인 네트워크 인스턴스
    mycontract : meta_contract 함수 인스턴스
    sender : 매타트랜잭션을 이용해서 토큰을 전송하려는 사용자
    sender_pk : 사용자의 개인키
    recipients : 받는 사람의 list
    amounts : 받을 erc 20 토큰 수량 list
    token_contract_add : erc 20 토큰 contract address
    fee_payer : 메타트랜잭션 대납자 주소
    fee_payer_pk : 대납자의 개인키 주소
    gas_price : 트랜잭션을 수행할 가스단가
    '''

    fee_payer = web3.to_checksum_address(fee_payer)
    signature = make_signaute(web3, mycontract, sender, sender_pk, recipients, amounts, token_contract_add)
    gas_estimate = mycontract.functions.transfer(sender ,amounts, recipients, token_contract_add, signature).estimate_gas({'from': fee_payer})
    print(gas_estimate)
    nonce = web3.eth.get_transaction_count(fee_payer)
    print(nonce)
    print(f"txfee: {web3.from_wei(gas_estimate * gas_price, 'Ether')}")
    tx = mycontract.functions.transfer(sender ,amounts, recipients, token_contract_add, signature).build_transaction({
        'from': fee_payer,
        'nonce': nonce,
        'gasPrice': gas_price,
        'gas': gas_estimate

    })
    signed_txn = web3.eth.account.sign_transaction(tx, fee_payer_pk)
    amtTxHash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    gncHash = web3.eth.wait_for_transaction_receipt(amtTxHash)
    return gncHash

def eth_meta_make_signaute(web3, mycontract, sender, sender_pk, recipients, amounts, token_contract_add):
    '''
    use : sender의 사인값 추출 함수
    web3 : 체인 네트워크 인스턴스
    mycontract : meta_contract 함수 인스턴스
    sender : 토큰 전송하는 사용자
    sender_pk : 전송자의 개인키
    recipients : 받는사람 list
    amounts : 받을 수량 list
    token_contract_add : erc 20 토큰 contract address
    '''

    sender = web3.to_checksum_address(sender)
    for i in range(len(recipients)):
        recipients[i] = web3.to_checksum_address(recipients[i])
    token_contract_add = web3.to_checksum_address(token_contract_add)
    check = mycontract.functions.checkAddressInWhitelist(token_contract_add).call()
    if check == True:
        contract_nonce = mycontract.functions.nonces(sender).call()
        hash = mycontract.functions.getHash(sender, amounts, recipients, token_contract_add, contract_nonce).call()
        signed_message = web3.eth.account.sign_message(encode_defunct(hash), private_key=sender_pk)
        signature = signed_message.signature.hex()
        confirm = web3.eth.account.recover_message(encode_defunct(hash) ,signature = signed_message.signature)
        if (sender == confirm):
            return signature
        else: 
            print("Signature does not come from sender")
    else:
         print("tokenContract is not whitelisted")

def eth_meta_addWhitelist(web3,mycontract, owner_add, owner_pk, token_contract_add, gas_price):
    '''
    use : meta_contract에 erc 20 contaract address 를 화이트리스트에 등록하는 트랙잭션 이것을 안하면 메타트랙잭션 사용불가
    web3 : 체인 네트워크 인스턴스
    mycontract : meta_contract 함수 인스턴스
    owner_add : meta_contract의 owner
    owner_pk : owner의 개인키
    token_contract_add : 화이트리스트에 등록 할 erc 20 contract address
    gas_price : 트랜잭션에 사용할 가스단가
    '''

    owner_add = web3.to_checksum_address(owner_add)
    token_contract_add = web3.to_checksum_address(token_contract_add)
    gas_estimate = mycontract.functions.addToWhitelist(token_contract_add).estimate_gas({'from': owner_add})
    nonce = web3.eth.get_transaction_count(owner_add)
    print(f"txfee: {web3.from_wei(gas_estimate * gas_price, 'Ether')}")
    tx = mycontract.functions.addToWhitelist(token_contract_add).build_transaction({
        'from': owner_add,
        'nonce': nonce,
        'gasPrice': gas_price,
        'gas': gas_estimate

    })
    signed_txn = web3.eth.account.sign_transaction(tx, owner_pk)
    amtTxHash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    gncHash = web3.eth.wait_for_transaction_receipt(amtTxHash)
    return gncHash
     

def remove_white_list(web3, mycontract, owner_add,owner_pk, token_contract_add, gas_price):
    '''
    use : erc 20 contract address를 화이트리스트에서 제거
    web3 : 체인 네트워크 인스턴스
    mycontract : meta_contract 함수 인스턴스
    owner_add : meta_contract의 owner
    owner_pk : owner의 개인키
    token_contract_add : 화이트리스트에 제거 할 erc 20 contract address
    gas_price : 트랜잭션에 사용할 가스단가
    
    '''
    owner_add = web3.to_checksum_address(owner_add)
    token_contract_add = web3.to_checksum_address(token_contract_add)

    gas_estimate = mycontract.functions.removeFromWhitelist(token_contract_add).estimate_gas({'from': owner_add})
    nonce = web3.eth.get_transaction_count(owner_add)

    print(f"txfee: {web3.from_wei(gas_estimate * gas_price, 'Ether')}")
    tx = mycontract.functions.removeFromWhitelist(token_contract_add).build_transaction({
        'from': owner_add,
        'nonce': nonce,
        'gasPrice': gas_price,
        'gas': gas_estimate

    })
    signed_txn = web3.eth.account.sign_transaction(tx, owner_pk)
    amtTxHash = web3.eth.send_raw_transaction(signed_txn.rawTransaction)
    gncHash = web3.eth.wait_for_transaction_receipt(amtTxHash)
    return gncHash
      
def trade_list(web3,mycontract,startBlock,fromadress = None):
    '''
        use              : filter를 이용해서 거래내역을 가져온다
        input parameter  : 1. web3 : web3 네트워크 연결
                           2. mycontract : abi로 활성화한 컨트랙트 함수들
                           3. startBlock : 토큰이 거래가시작되는 블록
                           4. fromadress : 발신자 주소를 지정하면 그주소에 관한 거래 내역이 출력된다 (선택사항)
        output parameter : tx_list
    '''
    tx_list = []
    if fromadress is None:
        myFilter =  mycontract.events.metatran.create_filter(fromBlock=startBlock)
    else:
        myFilter =  mycontract.events.metatran.create_filter(fromBlock=startBlock, argument_filters={'from': fromadress})
    txs = myFilter.get_all_entries()
    for tx in txs:
        tx_hash = (tx.transactionHash).hex()
        getblock = web3.eth.get_block(tx.blockNumber).timestamp
        date = datetime.datetime.fromtimestamp(int(getblock)).strftime('%Y-%m-%d %H:%M:%S')
        tx_data = {'sender': tx.args['sender'],'recipients':tx.args['recipients'], 'token_contract_add': tx.args['token_contract_add'], 'amounts': tx.args['amounts'], 'event': tx.event,'transactionHash': tx_hash, 'blockNumber': tx.blockNumber ,'date': date }

        tx_list.append(tx_data)
    return tx_list

if __name__ == "__main__":
    
