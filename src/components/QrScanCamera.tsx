import { useEffect, useRef, useState } from "react";
import jsQR from "jsqr";

interface Props {
  disabled?: boolean;
  onScan: (ticketText: string) => void;
  onError: (message: string) => void;
}

/** Camera-only QR decoding. The decoded public ticket is immediately handed
 * to the parent; this component neither stores nor sends it anywhere. */
const QrScanCamera = ({ disabled = false, onScan, onError }: Props) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const onScanRef = useRef(onScan);
  const onErrorRef = useRef(onError);
  const [active, setActive] = useState(false);

  useEffect(() => { onScanRef.current = onScan; }, [onScan]);
  useEffect(() => { onErrorRef.current = onError; }, [onError]);

  useEffect(() => {
    if (disabled || !navigator.mediaDevices?.getUserMedia) return;
    let stream: MediaStream | null = null;
    let frame = 0;
    let settled = false;

    const stop = () => {
      if (frame) cancelAnimationFrame(frame);
      stream?.getTracks().forEach((track) => track.stop());
      setActive(false);
    };
    const scanFrame = () => {
      const video = videoRef.current;
      const canvas = canvasRef.current;
      if (!video || !canvas || settled) return;
      if (video.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && video.videoWidth && video.videoHeight) {
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        const context = canvas.getContext("2d", { willReadFrequently: true });
        if (context) {
          const image = context.getImageData(0, 0, canvas.width, canvas.height);
          const result = jsQR(image.data, image.width, image.height, { inversionAttempts: "dontInvert" });
          if (result?.data) {
            settled = true;
            stop();
            onScanRef.current(result.data);
            return;
          }
        }
      }
      frame = requestAnimationFrame(scanFrame);
    };

    navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false })
      .then((captured) => {
        if (settled) {
          captured.getTracks().forEach((track) => track.stop());
          return;
        }
        stream = captured;
        const video = videoRef.current;
        if (!video) return;
        video.srcObject = captured;
        void video.play().then(() => {
          setActive(true);
          frame = requestAnimationFrame(scanFrame);
        });
      })
      .catch(() => onErrorRef.current("Camera access is required to scan a transfer code. You can enter the code manually instead."));

    return () => { settled = true; stop(); };
  }, [disabled]);

  return (
    <div className="space-y-2">
      <div className="relative overflow-hidden rounded-xl border border-white/10 bg-black aspect-square">
        <video ref={videoRef} muted playsInline className="h-full w-full object-cover" />
        <canvas ref={canvasRef} className="hidden" aria-hidden="true" />
        {!active && !disabled && <span className="absolute inset-0 grid place-items-center text-xs text-zinc-400">Starting camera…</span>}
      </div>
      <p className="text-center text-[11px] text-zinc-500">Point the camera at the QR code. Nothing is saved.</p>
    </div>
  );
};

export default QrScanCamera;
