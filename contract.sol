pragma solidity ^ 0.4 .24;

contract sign {

    struct stamp {
        bytes32 blockhash;
        bytes32 commit;
        bytes32 reveal;
        bytes32 noncedHash;
        uint timestamp; //time in epoch time
        uint submissionDate;
        mapping(uint8 => bytes) signature;
        mapping(uint8 => bool) isSigned;
        mapping(uint8 => address) signer;
        uint8 signerCount;
        uint256 stampNumber;
    }

    mapping(uint256 => stamp) public stamps;
    mapping(bytes32 => uint256) public lookUp;
    uint256 currentStamp = 0;

    //constructor makes a new stamp incrimentally.
    function newStamp(uint8 signerCount, bytes32 commit, address[] signerArg) public {
        require(signerArg.length == signerCount);
        //require(lookUp[bytes32] == null); //need to hard code this somehow

        stamps[currentStamp].commit = commit;
        stamps[currentStamp].blockhash = block.blockhash(block.number - 1);
        stamps[currentStamp].noncedHash = keccak256(commit, stamps[currentStamp].blockhash);
        stamps[currentStamp].signerCount = signerCount;
        stamps[currentStamp].stampNumber = currentStamp;
        stamps[currentStamp].submissionDate = block.timestamp;
        lookUp[commit] = currentStamp;

        for (uint8 x = 0; x < signerCount; x++)
            stamps[currentStamp].signer[x] = signerArg[x];

        currentStamp++;
    }

    function getStampNumber(bytes32 commit) public constant returns (uint256){
        return lookUp[commit];
    }

    //with a salt and preimage, reveal preimage at a later time
    function reveal(uint256 arg, bytes32 hash, bytes32 salt) public returns(bool) {
        require(sha3(hash, salt) == stamps[arg].commit);
        stamps[arg].reveal = hash;
        return true;
    }


    //set signature. record time when all cosigners signed if all have signed.
    function setSignature(uint256 stampNumber, uint8 signerPos, bytes signature) public returns(bool) {
        require(!stamps[stampNumber].isSigned[signerPos]);
        require(stamps[stampNumber].timestamp == 0);
        //check that noncedHash was signed by signer[signerPos]. Throw if otherwise//
        require(smartVerf.ecverify(stamps[stampNumber].noncedHash, signature, stamps[stampNumber].signer[signerPos]));

        stamps[stampNumber].isSigned[signerPos] = true; //make this function uncallable for this stamp
        stamps[stampNumber].signature[signerPos] = signature;

        //officially date the stmap
        if (isAllSigned(stampNumber))
            stamps[stampNumber].timestamp = block.timestamp;

        return true;
    }


    function isAllSigned(uint256 stampNumber) private constant returns(bool) {
        for (uint8 x = 0; x < stamps[stampNumber].signerCount; x++)
            if (stamps[stampNumber].isSigned[x] == false)
                return false;

        return true;
    }

    function getTimeStamp(uint256 arg) public constant returns(uint256) {
        return stamps[arg].timestamp;
    }
}


//credit to https://gist.github.com/axic
library smartVerf{
    function safer_ecrecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal returns (bool, address) {
        // We do our own memory management here. Solidity uses memory offset
        // 0x40 to store the current end of memory. We write past it (as
        // writes are memory extensions), but don't update the offset so
        // Solidity will reuse it. The memory used here is only needed for
        // this context.

        // FIXME: inline assembly can't access return values
        bool ret;
        address addr;

        assembly {
            let size := mload(0x40)
            mstore(size, hash)
            mstore(add(size, 32), v)
            mstore(add(size, 64), r)
            mstore(add(size, 96), s)

            // NOTE: we can reuse the request memory because we deal with
            //       the return code
            ret := call(3000, 1, 0, size, 128, size, 32)
            addr := mload(size)
        }

        return (ret, addr);
    }

    function ecrecovery(bytes32 hash, bytes sig) returns (bool, address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        if (sig.length != 65)
          return (false, 0);

        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))

            // Here we are loading the last 32 bytes. We exploit the fact that
            // 'mload' will pad with zeroes if we overread.
            // There is no 'mload8' to do this, but that would be nicer.
            v := byte(0, mload(add(sig, 96)))

            // Alternative solution:
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            // v := and(mload(add(sig, 65)), 255)
        }

        if (v < 27)
          v += 27;

        if (v != 27 && v != 28)
            return (false, 0);

        return safer_ecrecover(hash, v, r, s);
    }

    function ecverify(bytes32 hash, bytes sig, address signer) returns (bool) {
        bool ret;
        address addr;
        (ret, addr) = ecrecovery(hash, sig);
        return ret == true && addr == signer;
    }
}
