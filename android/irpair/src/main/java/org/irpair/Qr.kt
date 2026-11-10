package org.irpair

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import java.util.concurrent.Executors

/** irpair's QR codes: what they carry is sealed by the irpair crate
 *  (`seal_qr`) under a password, so a code seen by anything else gives
 *  nothing away. */
object Qr {
    internal const val PREFIX = "IRPAIR1:"

    /** The code for [text], [size] pixels square. */
    fun bitmap(text: String, size: Int): Bitmap {
        val hints = mapOf(EncodeHintType.MARGIN to 2)
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        val px = IntArray(size * size) { if (m[it % size, it / size]) Color.BLACK else Color.WHITE }
        return Bitmap.createBitmap(px, size, size, Bitmap.Config.ARGB_8888)
    }
}

/** Scan an irpair QR code with the camera: its text, or null. */
class ScanQr : ActivityResultContract<Unit, String?>() {
    override fun createIntent(context: Context, input: Unit) =
        Intent(context, ScanActivity::class.java)

    override fun parseResult(resultCode: Int, intent: Intent?): String? =
        intent?.getStringExtra(TEXT).takeIf { resultCode == Activity.RESULT_OK }

    internal companion object {
        const val TEXT = "text"
    }
}

/** The camera until an irpair code is in view: frames are read in memory,
 *  none kept, nothing sent, and the screen cannot be captured. */
class ScanActivity : ComponentActivity() {
    private val reader = MultiFormatReader().apply {
        setHints(mapOf(DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE)))
    }
    private val work = Executors.newSingleThreadExecutor()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        val view = PreviewView(this)
        setContentView(view)
        val ask = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
            if (it) start(view) else finish()
        }
        val granted = checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        if (granted) start(view) else ask.launch(Manifest.permission.CAMERA)
    }

    private fun start(view: PreviewView) {
        val provider = ProcessCameraProvider.getInstance(this)
        provider.addListener({
            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(view.surfaceProvider)
            val scan = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            scan.setAnalyzer(work) { img -> img.use { decode(it)?.let(::done) } }
            provider.get().run {
                unbindAll()
                bindToLifecycle(this@ScanActivity, CameraSelector.DEFAULT_BACK_CAMERA, preview, scan)
            }
        }, mainExecutor)
    }

    private fun decode(img: ImageProxy): String? {
        val y = img.planes[0]
        val data = ByteArray(y.buffer.remaining()).also { y.buffer.get(it) }
        val src = PlanarYUVLuminanceSource(data, y.rowStride, img.height, 0, 0, img.width, img.height, false)
        val text = runCatching { reader.decodeWithState(BinaryBitmap(HybridBinarizer(src))).text }
        reader.reset()
        return text.getOrNull()?.takeIf { it.startsWith(Qr.PREFIX) }
    }

    private fun done(text: String) = runOnUiThread {
        if (!isFinishing) {
            setResult(RESULT_OK, Intent().putExtra(ScanQr.TEXT, text))
            finish()
        }
    }

    override fun onDestroy() {
        work.shutdown()
        super.onDestroy()
    }
}
