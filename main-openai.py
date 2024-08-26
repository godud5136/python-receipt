import streamlit as st
import requests
import base64
import json
import time
import openai
import pyperclip

# from dotenv import load_dotenv
# import os

# load_dotenv()

openai.api_key = st.secrets("OPENAI_API_KEY")

def clova_ocr_request(image_data):
    # 이미지 데이터를 BASE64로 인코딩
    encoded_image = base64.b64encode(image_data).decode()

    # 요청에 필요한 데이터 구성
    request_data = {
        "version": "V2",
        "requestId": str(int(time.time())),
        "timestamp": int(time.time() * 1000),
        "lang": "ko",
        "images": [
            {
                "format": "jpg",
                "name": "ocr-test",
                "data": encoded_image
            }
        ]
    }

    headers = {
        "X-OCR-SECRET": st.secrets("CLOVA_OCR_SECRET_KEY"),
        "Content-Type": "application/json"
    }

    # Clova OCR API 호출
    response = requests.post(st.secrets("CLOVA_OCR_API_URL"), headers=headers, data=json.dumps(request_data))
    return response.json()

def extract_text_from_ocr_result(ocr_result):
    texts = []
    fields = ocr_result['images'][0]['fields']
    for field in fields:
        texts.append(field['inferText'])
    return texts

def analyze_receipt(texts):
    receipt_text = ' '.join(texts)
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant to analyze the purchase date, store name, and total amount from the receipt and output it in JSON format"},
            {"role": "user", "content": f"Please analyze the following receipt data: {receipt_text}. purchase date, store name, and total amount, and Extract the purchase date in YYMMDD format, and format the total amount without commas."},
        ]
    )

    analysis = response.choices[0].message['content']

    # JSON 포맷의 시작과 끝을 제거하고, 문자열을 정리하여 리턴
    cleaned_analysis = analysis.strip("```json").strip("```")
    

    return cleaned_analysis

def copy_to_clipboard(text):
    # 클립보드로 텍스트를 복사하는 함수
    pyperclip.copy(text)
    st.success("텍스트가 클립보드에 복사되었습니다.")

def main():
    st.title("Clova OCR API with Streamlit and ChatGPT Analysis")
    st.write("이미지를 업로드하여 텍스트 인식과 영수증 분석을 수행합니다.")

    if 'ctr' not in st.session_state:
        st.session_state['ctr'] = 0

    if 'docs' not in st.session_state:
        st.session_state['docs'] = []

    if 'result' not in st.session_state:
        st.session_state['result'] = []

    if 'analysis_done' not in st.session_state:
        st.session_state.analysis_done = False

    def uploader_callback():
        uploaded_files = st.session_state.get(str(st.session_state['ctr']), None)

        if uploaded_files is not None:
            for uploaded_file in uploaded_files:
                st.session_state['docs'].append(uploaded_file)
            st.session_state['ctr'] += 1

        
    # Use a unique key for each uploader to ensure reactivity
    st.file_uploader(
        label="File uploader", 
        on_change=uploader_callback, 
        key=str(st.session_state['ctr']), 
        accept_multiple_files=True
    )

    # Display the uploaded images
    if st.session_state['ctr'] > 0:
        unique_key = f'{st.session_state["ctr"] - 1}'

        if unique_key in st.session_state: 
            for _, img_data in enumerate(st.session_state[unique_key]):
                img_file = img_data
                st.write(f"파일명: {img_file.name}")
                # 업로드된 이미지를 읽어서 API 요청 수행
                image_data = img_file.read()
                
                with st.spinner(f"{img_file.name}에 대해 OCR 수행 중..."):
                    ocr_result = clova_ocr_request(image_data)

                # OCR 결과 출력 및 텍스트 추출
                if ocr_result:
                    st.write(f"OCR result for {img_file.name}:")
                    extracted_texts = extract_text_from_ocr_result(ocr_result)

                    with st.spinner(f"Analyzing receipt from {img_file.name}..."):
                        analysis_result = analyze_receipt(extracted_texts)
                        
                        try:
                            analysis_dict = json.loads(analysis_result)

                            purchase_date = analysis_dict.get('purchase_date', 'N/A')
                            store_name = analysis_dict.get('store_name', 'N/A')
                            total_amount = analysis_dict.get('total_amount', 'N/A')

                            st.session_state["result"].append({
                                "fileId": img_file.file_id,
                                "fileName": img_file.name,
                                "purchase_date": purchase_date,
                                "store_name": store_name,
                                "total_amount": total_amount,
                            })

                            # for idx, output in enumerate(unique_key):
                            #     st.write(purchase_date)

                            #     if st.button(purchase_date):
                            #         copy_to_clipboard(purchase_date)
                                # if st.button(f"식비_점심_{output['total_amount']}_{output['purchase_date']}_이해영", key=f"lunch_{idx}"):
                                #     copy_to_clipboard(f"식비_점심_{output['total_amount']}_{output['purchase_date']}_이해영")

                                # if st.button(str(output["total_amount"]), key=f"amount_{idx}"):
                                #     copy_to_clipboard(str(output["total_amount"]))


                                # if st.button(output["store_name"], key=f"store_{idx}"):
                                #     copy_to_clipboard(output["store_name"])


                            st.session_state.analysis_done = True
                            
                        except json.JSONDecodeError:
                            st.error("Failed to decode analysis result. Please check the format.")
                else:
                    st.error(f"OCR request failed: {img_file.name}")


    if st.session_state.analysis_done:
        for idx, output in enumerate(st.session_state["result"]):
            st.write(output["fileName"])

            if st.button(f"식비_점심_{output['total_amount']}_{output['purchase_date']}_김재익", key=f"lunch_{idx}"):
                copy_to_clipboard(f"식비_점심_{output['total_amount']}_{output['purchase_date']}_김재익")

            if st.button(str(output["total_amount"]), key=f"amount_{idx}"):
                copy_to_clipboard(str(output["total_amount"]))


            if st.button(output["store_name"], key=f"store_{idx}"):
                copy_to_clipboard(output["store_name"])



if __name__ == "__main__":
    main()