package com.example.moproapp

import CircuitInputs
import android.content.Context
import prepareCircuitInputs
import readFileInChunks
import uniffi.mopro.GenerateProofResult
import uniffi.mopro.generateCircomProof
import uniffi.mopro.verifyCircomProof


class Circuit(zkeyFile:String, vkeyFile:String, _rapidsnarkInputs: CircuitInputs, _rawIntpus:MutableMap<String, List<String>>, _context: Context) {

    var zkeyPath:String = ""
    var vkeyPath:String = ""
    lateinit var context: Context
    lateinit var rapidsnarkInputs: CircuitInputs
    lateinit var rawInputs: MutableMap<String, List<String>>
    // proof result
    lateinit var rapidsnarkProof: ProveResponse
    lateinit var arkworksProof: GenerateProofResult

    init {
        context = _context
        zkeyPath = getFilePathFromAssets(context,zkeyFile)
        vkeyPath = getFilePathFromAssets(context,vkeyFile)
        rapidsnarkInputs = _rapidsnarkInputs
        rawInputs = _rawIntpus
    }

    fun proveRapidSnark() {
        val zkpTools = ZKPTools(context)
        zkpTools.witnesscalcKeccak256_256_test(
            rapidsnarkInputs.circuitBuffer,
            rapidsnarkInputs.circuitSize,
            rapidsnarkInputs.jsonBuffer,
            rapidsnarkInputs.jsonSize,
            rapidsnarkInputs.wtnsBuffer,
            rapidsnarkInputs.wtnsSize,
            rapidsnarkInputs.errorMsg,
            rapidsnarkInputs.errorMsgMaxSize
        )

        rapidsnarkProof = groth16Prove(
            zkeyPath,
            rapidsnarkInputs.wtnsBuffer
        )
    }

    fun verifyRapidSnark():Boolean {
        val vkeyData : ByteArray = readFileInChunks(vkeyPath)
        return groth16Verify(
            rapidsnarkProof.proof,
            rapidsnarkProof.publicSignals,
            vkeyData.toString(Charsets.UTF_8)
        )
    }

    fun proveArkworks() {
        arkworksProof = generateCircomProof(zkeyPath, rawInputs)
    }

    fun verifyArkworks():Boolean {
        return verifyCircomProof(zkeyPath, arkworksProof.proof, arkworksProof.inputs)
    }
}