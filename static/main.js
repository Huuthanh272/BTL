// IIFE để đóng gói toàn bộ code, tránh ảnh hưởng biến toàn cục
(function () {
  "use strict";

  // --- HẰNG SỐ LIÊN QUAN ĐẾN DB (KHÔNG DÙNG TRONG BẢN NÀY) ---
  const DB_NAME = "SecureAudioDB";
  const DB_VERSION = 1;
  const STORE_NAME = "messages";
  let db;

  // --- THAM CHIẾU ĐẾN CÁC PHẦN TỬ DOM ---
  const usernameInput = document.getElementById("username-input"); // Ô nhập username
  const registerBtn = document.getElementById("register-btn"); // Nút đăng ký
  const statusLabel = document.getElementById("status-label"); // Nhãn trạng thái
  const publicKeyDisplay = document.getElementById("public-key-display"); // Hiển thị public key
  const recipientSelect = document.getElementById("recipient-select"); // Danh sách người nhận
  const refreshUsersBtn = document.getElementById("refresh-users-btn"); // Nút làm mới danh sách user
  const recordBtn = document.getElementById("record-btn"); // Nút ghi âm
  const sendBtn = document.getElementById("send-btn"); // Nút gửi tin nhắn
  const checkMailBtn = document.getElementById("check-mail-btn"); // Nút kiểm tra tin nhắn
  const clearPrivateKeyBtn = document.getElementById("clear-private-key-btn"); // Nút xóa private key
  const privateKeyInput = document.getElementById("private-key-input"); // Ô nhập private key
  const inbox = document.getElementById("inbox"); // Hộp thư đến
  const recordStatus = document.getElementById("record-status"); // Trạng thái ghi âm

  // --- TRẠNG THÁI ỨNG DỤNG ---
  const state = {
    username: null, // Tên người dùng hiện tại
    publicKeys: null, // { rsaPublicKey, signPublicKey } - chỉ lưu public key
    users: {}, // Danh sách user và public key của họ
    audioBlob: null, // Dữ liệu âm thanh đã ghi
    mediaRecorder: null, // Đối tượng ghi âm
    isRecording: false, // Cờ kiểm tra đang ghi âm
  };

  // --- HÀM HỖ TRỢ MÃ HÓA (Web Crypto API) ---

  // Tạo cặp khóa RSA-OAEP 2048-bit cho mã hóa/giải mã
  async function generateRsaKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // Cho phép export key
      ["encrypt", "decrypt"]
    );
  }

  // Tạo cặp khóa RSA-PSS 2048-bit cho ký/xác thực chữ ký
  async function generateSignKeyPair() {
    return await window.crypto.subtle.generateKey(
      {
        name: "RSA-PSS",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true, // Cho phép export key
      ["sign", "verify"]
    );
  }

  // Tạo khóa AES-CBC 256-bit cho mã hóa đối xứng (mã hóa nội dung tin nhắn)
  async function generateAesKey() {
    return await window.crypto.subtle.generateKey(
      {
        name: "AES-CBC",
        length: 256,
      },
      true, // Cho phép export key
      ["encrypt", "decrypt"]
    );
  }
  /*Quy trình mã hóa tin nhắn:
  - Tạo session key AES cho tin nhắn này
  - Mã hóa audio với AES key
  - Mã hóa AES key với RSA public key của người nhận
  - Tạo hash của dữ liệu đã mã hóa
  - Ký hash với private key của người gửi
  - Đóng gói tất cả thành packet */

  // Export key ra dạng base64 (spki cho public, pkcs8 cho private)
  async function exportKey(key, format = "spki") {
    const exported = await window.crypto.subtle.exportKey(format, key);
    return btoa(String.fromCharCode.apply(null, new Uint8Array(exported)));
  }

  // Import public key từ base64 (SPKI)
  async function importRsaPublicKey(keyB64, keyType = "RSA-OAEP") {
    const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
    const algo =
      keyType === "RSA-OAEP"
        ? { name: "RSA-OAEP", hash: "SHA-256" }
        : { name: "RSA-PSS", hash: "SHA-256" };
    return await window.crypto.subtle.importKey(
      "spki",
      keyBytes,
      algo,
      true,
      keyType === "RSA-OAEP" ? ["encrypt"] : ["verify"]
    );
  }

  // Import private key từ base64 (PKCS8)
  async function importRsaPrivateKey(keyB64, keyType = "RSA-OAEP") {
    const keyBytes = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
    const algo =
      keyType === "RSA-OAEP"
        ? { name: "RSA-OAEP", hash: "SHA-256" }
        : { name: "RSA-PSS", hash: "SHA-256" };
    return await window.crypto.subtle.importKey(
      "pkcs8",
      keyBytes,
      algo,
      true,
      keyType === "RSA-OAEP" ? ["decrypt"] : ["sign"]
    );
  }

  // Mã hóa dữ liệu với khóa AES
  async function aesEncrypt(dataBuffer, key) {
    const iv = window.crypto.getRandomValues(new Uint8Array(16)); // Sinh vector khởi tạo ngẫu nhiên
    const encryptedData = await window.crypto.subtle.encrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      dataBuffer
    );
    return { iv, encryptedData };
  }

  // Mã hóa khóa AES với public key RSA
  async function rsaEncrypt(dataBuffer, publicKey) {
    return await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      dataBuffer
    );
  }

  // Ký dữ liệu với private key RSA
  async function sign(dataBuffer, privateKey) {
    return await window.crypto.subtle.sign(
      { name: "RSA-PSS", saltLength: 32 },
      privateKey,
      dataBuffer
    );
  }

  // Giải mã dữ liệu với khóa AES
  async function aesDecrypt(encryptedData, key, iv) {
    return await window.crypto.subtle.decrypt(
      {
        name: "AES-CBC",
        iv: iv,
      },
      key,
      encryptedData
    );
  }

  // Giải mã khóa AES với private key RSA
  async function rsaDecrypt(encryptedData, privateKey) {
    return await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      encryptedData
    );
  }

  // Xác thực chữ ký với public key RSA
  async function verify(signature, data, publicKey) {
    return await window.crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      signature,
      data
    );
  }

  // Chuyển ArrayBuffer sang base64 (dùng để truyền dữ liệu nhị phân qua JSON)
  function arrayBufferToBase64(buffer) {
    let binary = "";
    const bytes = new Uint8Array(buffer);
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  // Chuyển base64 thành ArrayBuffer
  function base64ToArrayBuffer(b64) {
    const binaryString = window.atob(b64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // --- HÀM HỖ TRỢ GỌI API ---

  // Gửi yêu cầu đăng ký user lên server
  async function registerUser(username, rsaPublicKeyB64, signPublicKeyB64) {
    try {
      const response = await fetch("/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username,
          rsaPublicKey: rsaPublicKeyB64,
          signPublicKey: signPublicKeyB64,
        }),
      });
      const data = await response.json();
      if (data.status === "success") {
        statusLabel.textContent = `Đã đăng ký với tên: ${username}`;
        statusLabel.style.color = "#77dd77";
      } else {
        statusLabel.textContent = `Lỗi: ${data.message}`;
        statusLabel.style.color = "#ff6961";
      }
    } catch (error) {
      console.error("Lỗi đăng ký:", error);
      statusLabel.textContent = "Lỗi đăng ký.";
      statusLabel.style.color = "#ff6961";
    }
  }

  // Lấy danh sách user từ server
  async function getUsers() {
    try {
      const response = await fetch("/get_users");
      const data = await response.json();
      if (data.status === "success") {
        state.users = data.users;
        // Cập nhật danh sách người nhận
        recipientSelect.innerHTML =
          '<option value="">-- Chọn người nhận --</option>';
        for (const user in state.users) {
          if (user !== state.username) {
            // Không hiển thị chính mình
            const option = document.createElement("option");
            option.value = user;
            option.textContent = user;
            recipientSelect.appendChild(option);
          }
        }
      }
    } catch (error) {
      console.error("Lỗi lấy danh sách user:", error);
    }
  }

  // Gửi gói tin đã mã hóa lên server
  async function sendPacket(packet, recipient, sender) {
    try {
      const response = await fetch("/send", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipient, packet, sender }),
      });
      const data = await response.json();
      return data;
    } catch (error) {
      console.error("Lỗi gửi tin nhắn:", error);
      return { status: "error", message: "Gửi tin nhắn thất bại." };
    }
  }

  // Lấy tin nhắn từ server
  async function getMessages(username) {
    try {
      const response = await fetch(`/receive/${username}`);
      return await response.json();
    } catch (error) {
      console.error("Lỗi lấy tin nhắn:", error);
      return { status: "error", messages: [] };
    }
  }

  // --- HÀM HỖ TRỢ GIAO DIỆN ---

  // Hiển thị tin nhắn âm thanh đã giải mã lên giao diện
  function displayMessage(decryptedAudioBuffer, from, timestamp) {
    const audioBlob = new Blob([decryptedAudioBuffer], { type: "audio/wav" });
    const audioUrl = URL.createObjectURL(audioBlob);

    const messageDiv = document.createElement("div");
    messageDiv.className = "message";

    const info = document.createElement("p");
    info.innerHTML = `<strong>Từ:</strong> ${from}<br><strong>Thời gian:</strong> ${new Date(
      timestamp
    ).toLocaleString()}`;
    messageDiv.appendChild(info);

    const audioPlayer = document.createElement("audio");
    audioPlayer.controls = true;
    audioPlayer.src = audioUrl;
    messageDiv.appendChild(audioPlayer);

    inbox.appendChild(messageDiv);
    // Tự động cuộn xuống cuối khi có tin nhắn mới
    inbox.scrollTop = inbox.scrollHeight;
  }

  // Hiển thị thông báo dạng toast
  function showToast(message, type = "info") {
    const toast = document.getElementById("toast");
    toast.textContent = message;
    toast.style.background =
      type === "error"
        ? "linear-gradient(90deg, #e94e77 60%, #b9134f 100%)"
        : "linear-gradient(90deg, #4a90e2 60%, #357abd 100%)";
    toast.className = "show";
    setTimeout(() => {
      toast.className = toast.className.replace("show", "");
    }, 2500);
  }

  // --- LẮNG NGHE SỰ KIỆN GIAO DIỆN ---

  // Xử lý đăng ký người dùng mới
  registerBtn.addEventListener("click", async () => {
    const username = usernameInput.value.trim();
    if (!username) {
      showToast("Vui lòng nhập username.", "error");
      return;
    }

    statusLabel.textContent = "Đang tạo khóa...";
    state.username = username;

    // Tạo song song 2 cặp khóa: 1 cho mã hóa, 1 cho ký
    const [rsaKeys, signKeys] = await Promise.all([
      generateRsaKeyPair(),
      generateSignKeyPair(),
    ]);

    // Export public key để gửi lên server
    const [rsaPublicKeyB64, signPublicKeyB64] = await Promise.all([
      exportKey(rsaKeys.publicKey),
      exportKey(signKeys.publicKey),
    ]);

    // Export private key để user lưu trữ (hiển thị cho user copy)
    const [rsaPrivateKeyB64, signPrivateKeyB64] = await Promise.all([
      exportKey(rsaKeys.privateKey, "pkcs8"),
      exportKey(signKeys.privateKey, "pkcs8"),
    ]);

    // Lưu public key vào state
    state.publicKeys = {
      rsaPublicKey: rsaKeys.publicKey,
      signPublicKey: signKeys.publicKey,
    };

    publicKeyDisplay.value = `Encrypt Public Key: ${rsaPublicKeyB64.substring(
      0,
      30
    )}...\nSign Public Key: ${signPublicKeyB64.substring(
      0,
      30
    )}...\n\n=== LƯU Ý: LƯU PRIVATE KEYS DƯỚI ĐÂY ===\nRSA Private Key: ${rsaPrivateKeyB64}\nSign Private Key: ${signPrivateKeyB64}`;
    statusLabel.textContent = "Đang đăng ký với server...";

    await registerUser(username, rsaPublicKeyB64, signPublicKeyB64);
    await getUsers(); // Làm mới danh sách user sau khi đăng ký
  });

  // Làm mới danh sách user khi bấm nút
  refreshUsersBtn.addEventListener("click", getUsers);

  // Kiểm tra tin nhắn mới khi bấm nút
  checkMailBtn.addEventListener("click", async () => {
    if (!state.username || !state.publicKeys) {
      showToast("Vui lòng đăng ký trước khi kiểm tra tin nhắn.", "error");
      return;
    }

    const privateKeyText = privateKeyInput.value.trim();
    if (!privateKeyText) {
      showToast("Vui lòng nhập private key để giải mã tin nhắn.", "error");
      return;
    }

    // Import private key từ input (user copy vào)
    let rsaPrivateKey, signPrivateKey;
    try {
      // Tách private key từ input (theo format: RSA Private Key: xxx\nSign Private Key: yyy)
      const lines = privateKeyText.split("\n");
      let rsaPrivateKeyB64 = "",
        signPrivateKeyB64 = "";

      for (const line of lines) {
        if (line.startsWith("RSA Private Key:")) {
          rsaPrivateKeyB64 = line.replace("RSA Private Key:", "").trim();
        } else if (line.startsWith("Sign Private Key:")) {
          signPrivateKeyB64 = line.replace("Sign Private Key:", "").trim();
        }
      }

      if (!rsaPrivateKeyB64 || !signPrivateKeyB64) {
        showToast(
          "Private key không đúng định dạng. Vui lòng nhập cả RSA và Sign private keys.",
          "error"
        );
        return;
      }

      [rsaPrivateKey, signPrivateKey] = await Promise.all([
        importRsaPrivateKey(rsaPrivateKeyB64, "RSA-OAEP"),
        importRsaPrivateKey(signPrivateKeyB64, "RSA-PSS"),
      ]);
    } catch (error) {
      showToast("Private key không hợp lệ. Vui lòng kiểm tra lại.", "error");
      return;
    }

    checkMailBtn.disabled = true;
    checkMailBtn.textContent = "Đang kiểm tra...";
    inbox.innerHTML = ""; // Xóa hộp thư trước khi hiển thị mới

    await getUsers(); // Lấy danh sách user mới nhất

    const response = await getMessages(state.username);

    if (response.status === "success" && response.messages.length > 0) {
      let newMessagesFound = 0;
      for (const msg of response.messages) {
        try {
          // 1. Giải mã các thành phần của packet
          const iv = base64ToArrayBuffer(msg.packet.iv);
          const encryptedData = base64ToArrayBuffer(msg.packet.cipher);
          const receivedHash = base64ToArrayBuffer(msg.packet.hash);
          const signature = base64ToArrayBuffer(msg.packet.sig);
          const encryptedAesKey = base64ToArrayBuffer(msg.packet.aesKey);
          const senderUsername = msg.sender_username;

          // 2. Kiểm tra toàn vẹn dữ liệu bằng hash
          const calculatedHash = await window.crypto.subtle.digest(
            "SHA-256",
            encryptedData
          );
          if (
            arrayBufferToBase64(receivedHash) !==
            arrayBufferToBase64(calculatedHash)
          ) {
            throw new Error("Hash không khớp! Dữ liệu có thể đã bị thay đổi.");
          }

          // 3. Xác thực chữ ký số của người gửi
          const senderSignPublicKeyB64 =
            state.users[senderUsername].signPublicKey;
          const senderSignPublicKey = await importRsaPublicKey(
            senderSignPublicKeyB64,
            "RSA-PSS"
          );
          const isSignatureValid = await verify(
            signature,
            calculatedHash,
            senderSignPublicKey
          );
          if (!isSignatureValid) {
            throw new Error(
              "Chữ ký không hợp lệ! Người gửi không thể được xác thực."
            );
          }

          // 4. Giải mã AES key bằng private key của mình
          const decryptedAesKeyData = await rsaDecrypt(
            encryptedAesKey,
            rsaPrivateKey
          );
          const aesKey = await window.crypto.subtle.importKey(
            "raw",
            decryptedAesKeyData,
            { name: "AES-CBC" },
            true,
            ["decrypt"]
          );

          // 5. Giải mã nội dung tin nhắn
          const decryptedAudio = await aesDecrypt(encryptedData, aesKey, iv);

          // 6. Hiển thị tin nhắn lên giao diện
          displayMessage(
            decryptedAudio,
            senderUsername,
            new Date().toISOString()
          );
          newMessagesFound++;
        } catch (error) {
          console.error("Lỗi giải mã tin nhắn:", error);
          const errorDiv = document.createElement("div");
          errorDiv.className = "message";
          errorDiv.style.borderColor = "#ff6961";
          errorDiv.innerHTML = `<p><strong>Lỗi khi xử lý tin nhắn:</strong> ${error.message}</p>`;
          inbox.appendChild(errorDiv);
        }
      }
      if (newMessagesFound === 0) {
        inbox.innerHTML = "<p>Không có tin nhắn nào mới.</p>";
      }
    } else {
      inbox.innerHTML = "<p>Không có tin nhắn mới.</p>";
    }

    checkMailBtn.disabled = false;
    checkMailBtn.textContent = "Kiểm tra tin nhắn";
  });

  // Xử lý xóa private key khỏi ô nhập
  clearPrivateKeyBtn.addEventListener("click", () => {
    privateKeyInput.value = "";
    showToast("Đã xóa private key khỏi bộ nhớ.", "info");
  });

  // Tự động xóa private key khi rời khỏi trang để tăng bảo mật
  window.addEventListener("beforeunload", () => {
    privateKeyInput.value = "";
  });

  // Xóa private key khi tab không active để tăng bảo mật
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden") {
      privateKeyInput.value = "";
    }
  });

  // Xử lý ghi âm âm thanh
  recordBtn.addEventListener("click", async () => {
    if (state.isRecording) {
      if (state.mediaRecorder && state.mediaRecorder.state === "recording") {
        state.mediaRecorder.stop();
      }
      // Trạng thái sẽ được cập nhật trong onstop
    } else {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          audio: true,
        });
        state.mediaRecorder = new MediaRecorder(stream);
        const audioChunks = [];
        state.mediaRecorder.ondataavailable = (event) => {
          audioChunks.push(event.data);
        };
        state.mediaRecorder.onstop = () => {
          state.audioBlob = new Blob(audioChunks, { type: "audio/wav" });
          stream.getTracks().forEach((track) => track.stop());
          recordBtn.textContent = "Bắt đầu ghi âm";
          recordStatus.textContent = "Đã dừng. Sẵn sàng gửi.";
          state.isRecording = false;
          sendBtn.disabled = false;
          console.log("Đã dừng ghi âm, audioBlob:", state.audioBlob);
        };
        state.mediaRecorder.onerror = (e) => {
          showToast("Lỗi ghi âm: " + e.error.name, "error");
          recordBtn.textContent = "Bắt đầu ghi âm";
          recordStatus.textContent = "Lỗi ghi âm!";
          state.isRecording = false;
          sendBtn.disabled = true;
        };
        state.mediaRecorder.start();
        recordBtn.textContent = "Dừng ghi âm";
        recordStatus.textContent = "Đang ghi âm...";
        state.isRecording = true;
        sendBtn.disabled = true;
      } catch (err) {
        console.error("Lỗi ghi âm:", err);
        showToast("Không thể truy cập micro. Vui lòng cấp quyền.", "error");
      }
    }
  });

  // Xử lý gửi gói tin đã mã hóa lên server
  sendBtn.addEventListener("click", async () => {
    const recipient = recipientSelect.value;
    if (!recipient) {
      showToast("Vui lòng chọn người nhận.", "error");
      return;
    }
    if (!state.audioBlob) {
      showToast("Vui lòng ghi âm trước khi gửi.", "error");
      return;
    }

    // Kiểm tra private key để ký tin nhắn
    const privateKeyText = privateKeyInput.value.trim();
    if (!privateKeyText) {
      showToast("Vui lòng nhập private key để ký tin nhắn.", "error");
      return;
    }

    // Import private key từ input
    let signPrivateKey;
    try {
      const lines = privateKeyText.split("\n");
      let signPrivateKeyB64 = "";

      for (const line of lines) {
        if (line.startsWith("Sign Private Key:")) {
          signPrivateKeyB64 = line.replace("Sign Private Key:", "").trim();
          break;
        }
      }

      if (!signPrivateKeyB64) {
        showToast(
          "Không tìm thấy Sign Private Key. Vui lòng kiểm tra lại.",
          "error"
        );
        return;
      }

      signPrivateKey = await importRsaPrivateKey(signPrivateKeyB64, "RSA-PSS");
    } catch (error) {
      showToast(
        "Sign Private Key không hợp lệ. Vui lòng kiểm tra lại.",
        "error"
      );
      return;
    }

    try {
      sendBtn.disabled = true;
      recordStatus.textContent = "Đang mã hóa...";

      // 1. Chuyển audio blob thành ArrayBuffer
      const audioBuffer = await state.audioBlob.arrayBuffer();

      // 2. Lấy public key của người nhận từ server
      const recipientRsaPublicKeyB64 = state.users[recipient].rsaPublicKey;
      const recipientRsaPublicKey = await importRsaPublicKey(
        recipientRsaPublicKeyB64,
        "RSA-OAEP"
      );

      // 3. Tạo khóa phiên AES
      const aesKey = await generateAesKey();

      // 4. Mã hóa khóa AES bằng public key của người nhận
      const exportedAesKey = await window.crypto.subtle.exportKey(
        "raw",
        aesKey
      );
      const encryptedAesKey = await rsaEncrypt(
        exportedAesKey,
        recipientRsaPublicKey
      );

      // 5. Mã hóa dữ liệu audio bằng AES
      const { iv, encryptedData } = await aesEncrypt(audioBuffer, aesKey);

      // 6. Tạo hash và ký hash bằng private key
      const hashBuffer = await window.crypto.subtle.digest(
        "SHA-256",
        encryptedData
      );
      const signature = await sign(hashBuffer, signPrivateKey);

      // 7. Đóng gói tất cả thành packet
      const packet = {
        iv: arrayBufferToBase64(iv),
        cipher: arrayBufferToBase64(encryptedData),
        hash: arrayBufferToBase64(hashBuffer),
        sig: arrayBufferToBase64(signature),
        aesKey: arrayBufferToBase64(encryptedAesKey),
      };

      // 8. Gửi packet lên server
      recordStatus.textContent = "Đang gửi...";
      const result = await sendPacket(packet, recipient, state.username);
      if (result.status === "success") {
        showToast("Gửi tin nhắn thành công!", "info");
      } else {
        showToast(`Lỗi: ${result.message}`, "error");
      }
      recordStatus.textContent = "Đã gửi. Sẵn sàng ghi âm mới.";
    } catch (error) {
      console.error("Lỗi mã hóa hoặc gửi:", error);
      showToast("Đã xảy ra lỗi trong quá trình gửi.", "error");
      recordStatus.textContent = "Lỗi!";
    } finally {
      sendBtn.disabled = false;
      state.audioBlob = null; // Reset audio blob
    }
  });

  // Kết nối WebSocket (Socket.IO) để nhận tin nhắn realtime
  const socket = io();

  socket.on("connect", () => {
    console.log("Đã kết nối WebSocket tới server");
  });

  // Lắng nghe sự kiện nhận tin nhắn mới từ server
  socket.on("new_message", async (data) => {
    // data: { recipient, message }
    if (!state.username || !state.publicKeys) return;
    if (data.recipient !== state.username) return;

    // Kiểm tra private key để giải mã
    const privateKeyText = privateKeyInput.value.trim();
    if (!privateKeyText) {
      showToast(
        "Có tin nhắn mới nhưng cần nhập private key để giải mã.",
        "info"
      );
      return;
    }

    // Import private key từ input
    let rsaPrivateKey;
    try {
      const lines = privateKeyText.split("\n");
      let rsaPrivateKeyB64 = "";

      for (const line of lines) {
        if (line.startsWith("RSA Private Key:")) {
          rsaPrivateKeyB64 = line.replace("RSA Private Key:", "").trim();
          break;
        }
      }

      if (!rsaPrivateKeyB64) {
        showToast(
          "Không tìm thấy RSA Private Key để giải mã tin nhắn.",
          "error"
        );
        return;
      }

      rsaPrivateKey = await importRsaPrivateKey(rsaPrivateKeyB64, "RSA-OAEP");
    } catch (error) {
      showToast("RSA Private Key không hợp lệ để giải mã tin nhắn.", "error");
      return;
    }

    const msg = data.message;
    try {
      // 1. Giải mã các thành phần của packet
      const iv = base64ToArrayBuffer(msg.packet.iv);
      const encryptedData = base64ToArrayBuffer(msg.packet.cipher);
      const receivedHash = base64ToArrayBuffer(msg.packet.hash);
      const signature = base64ToArrayBuffer(msg.packet.sig);
      const encryptedAesKey = base64ToArrayBuffer(msg.packet.aesKey);
      const senderUsername = msg.sender_username;

      // 2. Kiểm tra toàn vẹn dữ liệu bằng hash
      const calculatedHash = await window.crypto.subtle.digest(
        "SHA-256",
        encryptedData
      );
      if (
        arrayBufferToBase64(receivedHash) !==
        arrayBufferToBase64(calculatedHash)
      ) {
        showToast("Hash không khớp! Dữ liệu có thể đã bị thay đổi.", "error");
        return;
      }

      // 3. Xác thực chữ ký số của người gửi
      const senderSignPublicKeyB64 = state.users[senderUsername].signPublicKey;
      const senderSignPublicKey = await importRsaPublicKey(
        senderSignPublicKeyB64,
        "RSA-PSS"
      );
      const isSignatureValid = await verify(
        signature,
        calculatedHash,
        senderSignPublicKey
      );
      if (!isSignatureValid) {
        showToast(
          "Chữ ký không hợp lệ! Người gửi không thể được xác thực.",
          "error"
        );
        return;
      }

      // 4. Giải mã AES key bằng private key của mình
      const decryptedAesKeyData = await rsaDecrypt(
        encryptedAesKey,
        rsaPrivateKey
      );
      const aesKey = await window.crypto.subtle.importKey(
        "raw",
        decryptedAesKeyData,
        { name: "AES-CBC" },
        true,
        ["decrypt"]
      );

      // 5. Giải mã nội dung tin nhắn
      const decryptedAudio = await aesDecrypt(encryptedData, aesKey, iv);

      // 6. Hiển thị tin nhắn lên giao diện
      displayMessage(decryptedAudio, senderUsername, new Date().toISOString());
      showToast("Bạn có tin nhắn âm thanh mới!", "info");
    } catch (error) {
      console.error("Lỗi giải mã tin nhắn (WebSocket):", error);
      showToast("Lỗi khi xử lý tin nhắn mới!", "error");
    }
  });

  // --- KHỞI TẠO ỨNG DỤNG ---
  async function main() {
    // Không còn tự động đăng nhập lại, không còn localStorage
    // Luôn cho phép đăng ký lại username
    // Không đăng ký event listeners ở đây nữa
  }
  main();
})();
