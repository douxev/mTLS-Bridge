package com.douxev.mtls_bridge.ui.remote

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.douxev.mtls_bridge.R
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/** Black-on-white QR code (readable even with the dark theme). */
@Composable
fun QrCode(content: String, size: Dp, modifier: Modifier = Modifier) {
    val bitmap = remember(content) { encode(content) }
    Image(
        bitmap = bitmap,
        contentDescription = stringResource(R.string.remote_qr_description),
        // One module = several pixels: no smoothing, otherwise the QR code gets blurry.
        filterQuality = FilterQuality.None,
        modifier = modifier
            .background(Color.White)
            .padding(8.dp)
            .size(size),
    )
}

private fun encode(content: String): ImageBitmap {
    val hints = mapOf(
        EncodeHintType.MARGIN to 0,
        EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
    )
    // Size 0: one cell per module, scaled by Compose.
    val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, 0, 0, hints)
    val w = matrix.width
    val h = matrix.height
    val pixels = IntArray(w * h) { i ->
        if (matrix[i % w, i / w]) android.graphics.Color.BLACK else android.graphics.Color.WHITE
    }
    return Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888).asImageBitmap()
}
