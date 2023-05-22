# metatransaction_python
approve를 이용한 메타트랜잭션
사용법: 
meta_fowarder.sol 배포 -> erc 20 컨트랙트에서 metatran을 이용할 사람이 meta_fowarder contract address에 approve(approve 수량이 많으면 계속 메타트랜잭션을 사용가능함)
-> erc 20 컨트랙트 주소를 add whitelist를 사용해서 등록 (meta_fowarder owner가 등록해줘야함) -> make_signature을 이용해 사인 생성후 meta_transfer 실행

