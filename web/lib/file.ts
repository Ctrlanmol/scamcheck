export const MAX_UPLOAD = 20 * 1024 * 1024;

export function fileToBase64(file: File): Promise<string> {
  if (file.size > MAX_UPLOAD) {
    return Promise.reject(new Error("File is larger than 20 MB."));
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = String(reader.result || "");
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(new Error("Could not read the file."));
    reader.readAsDataURL(file);
  });
}
