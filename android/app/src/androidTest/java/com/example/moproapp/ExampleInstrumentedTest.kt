package com.example.moproapp

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import getKeccak256Inputs

import org.junit.Test
import org.junit.runner.RunWith

import org.junit.Assert.*
import prepareCircuitInputs

/**
 * Instrumented test, which will execute on an Android device.
 *
 * See [testing documentation](http://d.android.com/tools/testing).
 */
@RunWith(AndroidJUnit4::class)
class BenchmarckTest {
    @Test
    fun useAppContext() {
        // Context of the app under test.
        val appContext = InstrumentationRegistry.getInstrumentation().targetContext
        assertEquals("com.example.moproapp", appContext.packageName)
    }

    @Test
    fun keccak() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val keccak256Inputs = getKeccak256Inputs()
        val circuitPath = getFilePathFromAssets(context,  "keccak256_256_test.dat")
        val inputJsonPath = getFilePathFromAssets(context,  "keccak256.json")
        // prepare rapidsnark inputs
        val rapidsnarkInputs = prepareCircuitInputs(
            circuitPath,
            inputJsonPath,
        )
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

        // Init Circuit object
        val c = Circuit(
            "keccak256_256_test_final.zkey",
            "keccak256_256_test.json",
            rapidsnarkInputs,
            keccak256Inputs,
            context
        )

        val repeat = 5
        // Arkworks
        var startTime = System.currentTimeMillis()
        for (i in 1..repeat) {
            c.proveArkworks()
        }
        var endTime = System.currentTimeMillis()
        val provingTimeArkworks = (endTime - startTime) / repeat
        assert(c.verifyArkworks())

        // RapidSnark
        startTime = System.currentTimeMillis()
        for (i in 1..repeat) {
            c.proveRapidSnark()
        }
        endTime = System.currentTimeMillis()
        val provingTimeRapidSnark = (endTime - startTime) / repeat
        assert(c.verifyRapidSnark())

        // print out the results
        println("*** keccak256 ARKWORKS proving time: $provingTimeArkworks ms ***")
        println("*** keccak256 RAPIDSNARK proving time: $provingTimeRapidSnark ms ***")
    }
}