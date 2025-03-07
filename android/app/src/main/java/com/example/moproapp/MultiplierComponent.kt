import android.os.Build
import androidx.annotation.RequiresApi
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.moproapp.ZKPTools
import com.example.moproapp.getFilePathFromAssets
import com.example.moproapp.groth16Prove
import com.example.moproapp.groth16Verify
import uniffi.mopro.GenerateProofResult
import uniffi.mopro.generateCircomProof
import uniffi.mopro.toEthereumInputs
import uniffi.mopro.verifyCircomProof
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.nio.file.Files
import java.nio.file.Paths

@RequiresApi(Build.VERSION_CODES.O)
@Composable
fun MultiplierComponent() {
    var initTime by remember { mutableStateOf("init time:") }
    var provingTime by remember { mutableStateOf("proving time:") }
    var verifyingTime by remember { mutableStateOf("verifying time: ") }
    var valid by remember { mutableStateOf("valid:") }
    var output by remember { mutableStateOf("output:") }
    var res by remember {
        mutableStateOf<GenerateProofResult>(
            GenerateProofResult(proof = ByteArray(size = 0), inputs = ByteArray(size = 0))
        )
    }

    val inputs = mutableMapOf<String, List<String>>()
    inputs["a"] = listOf("3")
    inputs["b"] = listOf("5")

    var keccak256Inputs = getKeccak256Inputs()
    var sha256Inputs = getSha256Inputs()
    var rsaInputs = getRSAInputs()
    var semaphoreInputs = getSemaphoreInputs()
    var aadhaarInputs = getAadhaarInputs()

    val context = LocalContext.current
    val zkpTools = ZKPTools(context)

    val multiplier2ZkeyPath = getFilePathFromAssets(context, "multiplier2_final.zkey")
    val keccak256ZkeyPath = getFilePathFromAssets(context, "keccak256_256_test_final.zkey")
    val sha256ZkeyPath = getFilePathFromAssets(context, "sha256_512_final.zkey")
    val rsaZkeyPath = getFilePathFromAssets(context, "rsa_main_final.zkey")
    val semaphoreZkeyPath = getFilePathFromAssets(context, "semaphore-32.zkey")
    var aadhaarZkeyPath = getFilePathFromAssets(context, "circuit_final.zkey")

    var keccak256CircuitPath = getFilePathFromAssets(context, "keccak256_256_test.dat")
    var keccak256JsonPath = getFilePathFromAssets(context, "keccak256.json")
    var keccak256GraphPath = getFilePathFromAssets(context, "keccak256.bin")
    var keccak256WasmPath = getFilePathFromAssets(context, "keccak256_256_test.wasm")
    var keccak256VkeyPath = getFilePathFromAssets(context, "keccak256_256_test.json")

    var sha256CircuitPath = getFilePathFromAssets(context, "sha256_512.dat")
    var sha256JsonPath = getFilePathFromAssets(context, "sha256.json")
    var sha256GraphPath = getFilePathFromAssets(context, "sha256.bin")
    var sha256WasmPath = getFilePathFromAssets(context, "sha256_512.wasm")

    var semaphoreCircuitPath = getFilePathFromAssets(context, "semaphore.dat")
    var semaphoreJsonPath = getFilePathFromAssets(context, "semaphore-32.json")
    var semaphoreGraphPath = getFilePathFromAssets(context, "semaphore.bin")
    var semaphoreWasmPath = getFilePathFromAssets(context, "semaphore-32.wasm")

    var rsaCircuitPath = getFilePathFromAssets(context, "rsa_main.dat")
    var rsaJsonPath = getFilePathFromAssets(context, "rsa_main.json")
    var rsaWasmPath = getFilePathFromAssets(context, "rsa_main.wasm")

    var aadhaarWasmPath = getFilePathFromAssets(context, "aadhaar-verifier.wasm")

    Box(modifier = Modifier
        .fillMaxSize()
        .padding(16.dp), contentAlignment = Alignment.Center) {
        Button(
            onClick = {
                Thread(
                    Runnable {
                        val rapidsnarkInputs = prepareCircuitInputs(
                            keccak256CircuitPath,
                            keccak256JsonPath,
                        )
                        val startTime = System.currentTimeMillis()
                        var wtnsRes = zkpTools.witnesscalcKeccak256_256_test(
                            rapidsnarkInputs.circuitBuffer,
                            rapidsnarkInputs.circuitSize,
                            rapidsnarkInputs.jsonBuffer,
                            rapidsnarkInputs.jsonSize,
                            rapidsnarkInputs.wtnsBuffer,
                            rapidsnarkInputs.wtnsSize,
                            rapidsnarkInputs.errorMsg,
                            rapidsnarkInputs.errorMsgMaxSize
                        )


                        var proofRes = groth16Prove(
                            keccak256ZkeyPath,
                            rapidsnarkInputs.wtnsBuffer,

                        )

                        //res = generateCircomProof(rsaZkeyPath, rsaInputs)
                        val endTime = System.currentTimeMillis()
                        //println(toEthereumInputs(res.inputs))
                        println(proofRes)
                        println(rapidsnarkInputs.pubData.toString(Charsets.UTF_8))

                        var vkeyData : ByteArray = readFileInChunks(keccak256VkeyPath)
                        var verifyRes = groth16Verify(
                            proofRes.proof,
                            proofRes.publicSignals,
                            vkeyData.toString(Charsets.UTF_8),

                        )
                        println("verify res $verifyRes", )
                        
                        provingTime = "proving time: " + (endTime - startTime).toString() + " ms"
                    }
                ).start()
            },
            modifier = Modifier.padding(top = 20.dp)
        ) { Text(text = "generate proof") }
        Button(
            onClick = {
                val startTime = System.currentTimeMillis()
                //valid = "valid: " + verifyCircomProof(rsaZkeyPath, res.proof, res.inputs).toString()
                val endTime = System.currentTimeMillis()
                verifyingTime = "verifying time: " + (endTime - startTime).toString() + " ms"
                //output = "output: " + uniffi.mopro.toEthereumInputs(res.inputs)
            },
            modifier = Modifier.padding(top = 120.dp)
        ) { Text(text = "verify proof") }
        Text(
            text = "Multiplier proof",
            modifier = Modifier.padding(bottom = 180.dp),
            fontWeight = FontWeight.Bold
        )

        Text(text = provingTime, modifier = Modifier
            .padding(top = 250.dp)
            .width(200.dp))
        Text(text = valid, modifier = Modifier
            .padding(top = 300.dp)
            .width(200.dp))
        Text(text = verifyingTime, modifier = Modifier
            .padding(top = 350.dp)
            .width(200.dp))
        Text(text = output, modifier = Modifier
            .padding(top = 400.dp)
            .width(200.dp))
    }
}