import numpy as np
import streamlit as st
import secrets
import smtplib
import matplotlib.pyplot as plt
import time
from PIL import Image
from io import BytesIO
from email.mime.text import MIMEText
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Function to generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_key, public_key, private_pem, public_pem

# Function to send the private key via email
def send_private_key(email, private_key):
    sender_email = "shravyacsd0893@gmail.com"  # Replace with your email
    sender_password = "cuaysvqugkgedjqy"  # Replace with your email password
    subject = "Your Private Key for Decryption"
    message = f"Dear Receiver,\n\nHere is your private key for decryption:\n\n{private_key}\n\nKeep it safe and do not share it with anyone."

    msg = MIMEText(message)
    msg["From"] = sender_email
    msg["To"] = email
    msg["Subject"] = subject

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, msg.as_string())
        return True
    except Exception as e:
        st.sidebar.error(f"Failed to send email: {e}")
        return False

# Streamlit UI
st.title("🔐 Medical Image Encryption & Decryption Using JSMP + ECC")
st.sidebar.header("Upload Image")

# Generate ECC keys only once
if "public_key" not in st.session_state:
    private_key, public_key, private_pem, public_pem = generate_ecc_keys()
    st.session_state.update({
        "private_key": private_key,
        "public_key": public_key,
        "private_pem": private_pem,  # Keep private key secret
        "public_pem": public_pem,
        "chaotic_key": secrets.token_bytes(32)
    })

# Display only the public key
st.sidebar.write("✅ ECC Public Key Generated")
st.sidebar.text_area("Public Key", st.session_state["public_pem"], height=150, key="public_key_display")

# Receiver email input
receiver_email = st.sidebar.text_input("Receiver's Email")

if st.sidebar.button("Send Private Key"):
    if receiver_email:
        if send_private_key(receiver_email, st.session_state["private_pem"]):
            st.sidebar.success("✅ Private key sent successfully!")
    else:
        st.sidebar.error("❌ Please enter a valid email address!")

# Encryption and decryption functions...
def jsmp_chaotic_map(N, seed):
    chaos_sequence = np.zeros(N)
    x = (seed % 256) / 255.0
    alpha, beta = 2.0 + (seed % 10) * 0.01, 0.2 + (seed % 5) * 0.01

    for i in range(N):
        x = alpha * x * (1 - x) + beta * np.sin(np.pi * x)
        chaos_sequence[i] = x
    
    return chaos_sequence

def chaotic_encrypt(image, chaotic_key):
    img_array = np.array(image.convert("L"))
    h, w = img_array.shape
    seed = int.from_bytes(chaotic_key[:4], "big")
    chaos_sequence = jsmp_chaotic_map(h * w, seed)
    chaos_ints = (chaos_sequence * 255).astype(np.uint8)
    encrypted_pixels = np.bitwise_xor(img_array.flatten(), chaos_ints)
    return encrypted_pixels.reshape(h, w)

def chaotic_decrypt(encrypted_image, chaotic_key):
    h, w = encrypted_image.shape
    seed = int.from_bytes(chaotic_key[:4], "big")
    chaos_sequence = jsmp_chaotic_map(h * w, seed)
    chaos_ints = (chaos_sequence * 255).astype(np.uint8)
    decrypted_pixels = np.bitwise_xor(encrypted_image.flatten(), chaos_ints)
    return decrypted_pixels.reshape(h, w)

def plot_histogram(image, title):
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.hist(image.flatten(), bins=256, color="gray", alpha=0.7)
    ax.set_title(title)
    st.pyplot(fig)

def mse_psnr(original, decrypted):
    if original.shape != decrypted.shape:
        raise ValueError("Original and decrypted images must have the same shape")

    original = original.astype(np.float64)  # Convert to float for precision
    decrypted = decrypted.astype(np.float64)

    mse = np.mean((original - decrypted) ** 2)
    if mse == 0:
        return 0, float('inf')  # PSNR is infinite if images are identical
    
    psnr = 20 * np.log10(255.0 / np.sqrt(mse))
    return mse, psnr


uploaded_file = st.sidebar.file_uploader("Choose an Image", type=["png", "jpg", "jpeg"])
if uploaded_file:
    image = Image.open(uploaded_file)
    st.image(image, caption="🖼 Original Image", use_column_width=True)
    plot_histogram(np.array(image.convert("L")), "Histogram of Original Image")

    if st.sidebar.button("🔒 Encrypt Image"):
        encrypted_img = chaotic_encrypt(image, st.session_state["chaotic_key"])
        st.session_state["encrypted_img"] = encrypted_img
        encrypted_img_pil = Image.fromarray(encrypted_img)
        buf = BytesIO()
        encrypted_img_pil.save(buf, format="PNG")
        st.session_state["encrypted_img_bytes"] = buf.getvalue()
        
        st.image(encrypted_img_pil, caption="🔒 Encrypted Image", use_column_width=True)
        plot_histogram(encrypted_img, "Histogram of Encrypted Image")

        st.sidebar.download_button(
            "⬇ Download Encrypted Image",
            data=st.session_state["encrypted_img_bytes"],
            file_name="encrypted_image.png",
            mime="image/png"
        )

encrypted_file = st.sidebar.file_uploader("Upload Encrypted Image for Decryption", type=["png"])
if encrypted_file:
    encrypted_img = Image.open(encrypted_file)
    encrypted_img_array = np.array(encrypted_img)
    st.image(encrypted_img, caption="🔐 Encrypted Image", use_column_width=True)
    plot_histogram(encrypted_img_array, "Histogram of Uploaded Encrypted Image")

    user_private_key_input = st.sidebar.text_area("Enter Private Key for Decryption", height=150, key="decryption_key_input")

    if st.sidebar.button("🔓 Decrypt Image"):
        if user_private_key_input.strip() == st.session_state["private_pem"].strip():
            decrypted_img = chaotic_decrypt(encrypted_img_array, st.session_state["chaotic_key"])
            mse, psnr = mse_psnr(np.array(image.convert("L")), decrypted_img)
            st.sidebar.write(f"MSE: {mse:.2f}, PSNR: {psnr:.2f} dB")
            st.image(decrypted_img, caption="✅ Decrypted Image", use_column_width=True)
            plot_histogram(decrypted_img, "Histogram of Decrypted Image")
        else:
            st.sidebar.error("❌ Incorrect Private Key! Decryption Not Allowed.")