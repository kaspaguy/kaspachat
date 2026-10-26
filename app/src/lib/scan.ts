// QR scanning on the device: camera frames (or a picked image) decoded by jsQR in this page. Nothing leaves the device.
// The camera goes through getUserMedia everywhere (Android/iPhone web views, desktop, browsers); where there is no
// camera, or it is refused, the picked image still works.
import jsQR from 'jsqr';

export const canCamera = typeof navigator !== 'undefined' && !!navigator.mediaDevices?.getUserMedia;

function decode(src: CanvasImageSource, w: number, h: number, cv: HTMLCanvasElement): string | null {
  // Large photos are scaled down: jsQR's time grows with pixels, and 1,000 px is plenty for a QR code.
  const s = Math.min(1, 1000 / Math.max(w, h));
  cv.width = Math.round(w * s);
  cv.height = Math.round(h * s);
  const ctx = cv.getContext('2d', { willReadFrequently: true })!;
  ctx.drawImage(src, 0, 0, cv.width, cv.height);
  const img = ctx.getImageData(0, 0, cv.width, cv.height);
  return jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

// Starts the back camera in `video` and calls onCode with each decoded text until stopped.
export async function startCamera(video: HTMLVideoElement, onCode: (text: string) => void): Promise<() => void> {
  const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: 'environment' } }, audio: false });
  video.srcObject = stream;
  video.setAttribute('playsinline', '');
  video.muted = true;
  await video.play();
  const cv = document.createElement('canvas');
  let live = true;
  const tick = () => {
    if (!live) return;
    if (video.readyState >= 2 && video.videoWidth) {
      const text = decode(video, video.videoWidth, video.videoHeight, cv);
      if (text) onCode(text);
    }
    setTimeout(tick, 200);
  };
  tick();
  return () => {
    live = false;
    stream.getTracks().forEach((t) => t.stop());
    video.srcObject = null;
  };
}

export async function scanImage(file: Blob): Promise<string | null> {
  const bmp = await createImageBitmap(file);
  try {
    return decode(bmp, bmp.width, bmp.height, document.createElement('canvas'));
  } finally {
    bmp.close();
  }
}
