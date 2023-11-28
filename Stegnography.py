from PIL import Image
from Crypto.Cipher import AES
import os
import random
import wave
from moviepy.editor import VideoFileClip

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    return ciphertext

def decrypt_message(ciphertext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    decrypted_message_bytes = cipher.decrypt(ciphertext)

    return decrypted_message_bytes

def hide_message(input_path, output_path, message, key):
    # Encrypt the message
    encrypted_message = encrypt_message(message, key)
    binary_message = ''.join(format(byte, '08b') for byte in encrypted_message)

    # Determine the format of the file
    file_format = input_path.split('.')[-1].lower()

    if file_format in ['jpg', 'jpeg', 'png', 'bmp']:
        # For image formats (jpg, jpeg, png, bmp)
        img = Image.open(input_path)
        pixels = list(img.getdata())

        data_index = 0

        # Flatten the pixels list
        flattened_pixels = []

        # Loop through each pixel in order
        for i in range(len(pixels)):
            pixel = pixels[i]

            if isinstance(pixel, int):
                # Handle the case where pixel is an integer (grayscale image)
                pixel = (pixel,)

            for k in range(len(pixel)):  # Iterate over RGB or grayscale channels
                if data_index < len(binary_message):
                    # Update the least significant bit of the channel
                    pixel_channel = pixel[k]
                    pixel_channel = (pixel_channel & ~1) | int(binary_message[data_index])
                    pixel = pixel[:k] + (pixel_channel,) + pixel[k+1:]
                    data_index += 1

            # Append the flattened pixel to the list
            flattened_pixels.extend(pixel)

        # Create a new image with the modified pixel data
        img.putdata(flattened_pixels)
        img.save(output_path)

    elif file_format == 'wav':
        # For audio format (wav)
        audio = wave.open(input_path, 'rb')
        audio_frames = audio.readframes(audio.getnframes())
        audio_frames = bytearray(audio_frames)

        for i in range(len(binary_message)):
            if i < len(audio_frames):
                audio_frames[i] = (audio_frames[i] & 254) | int(binary_message[i])

        audio = wave.open(output_path, 'wb')
        audio.setparams(audio.getparams())
        audio.writeframes(audio_frames)
        audio.close()

    elif file_format in ['mp4', 'avi', 'mkv']:
        # For video formats (mp4, avi, mkv)
        video = VideoFileClip(input_path)
        video_audio = video.audio

        audio_frames = video_audio.to_soundarray().ravel()
        audio_frames = audio_frames.astype('int16')

        data_index = 0

        for i in range(len(audio_frames)):
            if data_index < len(binary_message):
                audio_frames[i] = (audio_frames[i] & 254) | int(binary_message[data_index])
                data_index += 1

        video_audio = audio_frames.tobytes()
        video = video.set_audio(video_audio)
        video.write_videofile(output_path, codec='libx264', audio_codec='aac')

    else:
        print("Unsupported file format.")

def retrieve_message(input_path, key):
    file_format = input_path.split('.')[-1].lower()

    if file_format in ['jpg', 'jpeg', 'png', 'bmp']:
        # For image formats (jpg, jpeg, png, bmp)
        img = Image.open(input_path)
        pixels = list(img.getdata())
        binary_message = ""

        # Loop through each pixel in order
        for pixel in pixels:
            if isinstance(pixel, int):
                # Handle the case where pixel is an integer (grayscale image)
                binary_message += str(pixel & 1)
            else:
                for k in range(len(pixel)):  # Iterate over RGB channels
                    binary_message += str(pixel[k] & 1)

        # Decrypt the message
        decrypted_message_bytes = decrypt_message(int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, 'big'), key)
        decrypted_message = decrypted_message_bytes.decode(errors='replace')

    elif file_format == 'wav':
        # For audio format (wav)
        audio = wave.open(input_path, 'rb')
        audio_frames = audio.readframes(audio.getnframes())
        audio_frames = bytearray(audio_frames)

        binary_message = ""
        for frame in audio_frames:
            binary_message += str(frame & 1)

        # Decrypt the message
        decrypted_message = decrypt_message(int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, 'big'), key)

    elif file_format in ['mp4', 'avi', 'mkv']:
        # For video formats (mp4, avi, mkv)
        video = VideoFileClip(input_path)
        video_audio = video.audio

        audio_frames = video_audio.to_soundarray().ravel()
        audio_frames = audio_frames.astype('int16')

        binary_message = ""
        for frame in audio_frames:
            binary_message += str(frame & 1)

        # Decrypt the message
        decrypted_message = decrypt_message(int(binary_message, 2).to_bytes((len(binary_message) + 7) // 8, 'big'), key)

    else:
        print("Unsupported file format.")
        return ""

    return decrypted_message

# Example usage:
input_path = "C:/Users/fahad/Downloads/IS_Project/input.png"
output_path = "C:/Users/fahad/Downloads/IS_Project/output_file.png"
message_to_hide = input("Enter the message to hide: ")
format_choice = input("Choose the format (image, audio, video): ").lower()
encryption_key = os.urandom(16)  # 128-bit key for AES

# Hide or retrieve the message based on the chosen format
if format_choice == 'image':
    hide_message(input_path, output_path, message_to_hide, encryption_key)
    retrieved_message = retrieve_message(output_path, encryption_key)
elif format_choice == 'audio':
    hide_message(input_path, output_path, message_to_hide, encryption_key)
    retrieved_message = retrieve_message(output_path, encryption_key)
elif format_choice == 'video':
    hide_message(input_path, output_path, message_to_hide, encryption_key)
    retrieved_message = retrieve_message(output_path, encryption_key)
else:
    print("Invalid format choice.")

# Print the results
print("Original message:", message_to_hide)
print("Retrieved message:", retrieved_message)
