import cv2
import time
import os

ASCII_CHARS = ["@", "#", "8", "&", "o", ":", "*", ".", " "]

def frame_to_ascii(frame, width=100, height=40):
    """Конвертирует кадр в ASCII"""
    resized_frame = cv2.resize(frame, (width, height))  
    ascii_frame = "\n".join(
        "".join(ASCII_CHARS[min(pixel // 28, len(ASCII_CHARS) - 1)] for pixel in row)  
        for row in resized_frame
    )
    return ascii_frame

def play_video_ascii(video_path, width=100, height=40):
    """Проигрывает видео в ASCII в одном квадрате в консоли"""
    cap = cv2.VideoCapture(video_path)

    if not cap.isOpened():
        print("Ошибка: Не удалось открыть видеофайл")
        return
    
    fps = int(cap.get(cv2.CAP_PROP_FPS))  
    frame_time = 1 / fps 

    os.system("cls" if os.name == "nt" else "clear")  

    while cap.isOpened():
        os.system("cls" if os.name == "nt" else "clear")
        ret, frame = cap.read()
        if not ret:
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0) 
            continue
        
        gray_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY) 
        ascii_art = frame_to_ascii(gray_frame, width, height)  
        
        print("\033[H", end="")  
        print(ascii_art, end='', flush=True)
        time.sleep(frame_time)  

    cap.release()

video_path = "C:/Pinterest/zxccat.mp4"  
play_video_ascii(video_path, width=100, height=40)