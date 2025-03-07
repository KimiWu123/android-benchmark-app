package com.example.moproapp

import CircuitInputs
import android.content.Context
import prepareCircuitInputs
import readFileInChunks
import uniffi.mopro.GenerateProofResult
import uniffi.mopro.generateCircomProof
import uniffi.mopro.verifyCircomProof


class Circuit(zkeyFile:String, vkeyFile:String, _rapidsnarkInputs: CircuitInputs, _rawIntpus:MutableMap<String, List<String>>, context: Context) {

    var zkeyPath:String = ""
    var vkeyPath:String = ""
    lateinit var rapidsnarkInputs: CircuitInputs
    lateinit var rawInputs: MutableMap<String, List<String>>
    // proof result
    lateinit var rapidsnarkProof: ProveResponse
    lateinit var arkworksProof: GenerateProofResult

    init {
        zkeyPath = getFilePathFromAssets(context,zkeyFile)
        vkeyPath = getFilePathFromAssets(context,vkeyFile)
        rapidsnarkInputs = _rapidsnarkInputs
        rawInputs = _rawIntpus
    }

    fun proveRapidSnark() {
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