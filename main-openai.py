import streamlit as st
import requests
import base64
import json
import time
import openai
from datetime import datetime

openai.api_key = st.secrets["OPENAI_API_KEY"]

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
        "X-OCR-SECRET": st.secrets["CLOVA_OCR_SECRET_KEY"],
        "Content-Type": "application/json"
    }

    # Clova OCR API 호출
    response = requests.post(st.secrets["CLOVA_OCR_API_URL"], headers=headers, data=json.dumps(request_data))
    return response.json()

def extract_text_from_ocr_result(ocr_result):
    texts = []
    fields = ocr_result['images'][0]['fields']
    for field in fields:
        texts.append(field['inferText'])
    return texts

def analyze_receipt(texts):
    receipt_text = ' '.join(texts)

    # GPT에게 커피 관련 항목을 분석하도록 지시하는 프롬프트 추가
    prompt = (
        f"Please analyze the following receipt data: {receipt_text}. "
        "Extract the purchase date in YYMMDD format, store name, and total amount. "
        "Also, determine if this receipt includes any coffee-related purchases (e.g., coffee, latte, espresso). "
        "If there is a coffee-related purchase, set the key 'coffee' to true, otherwise set it to false. "
        "Format the total amount without commas."
    )
    
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "system", "content": "You are a helpful assistant to analyze the purchase date, store name, and total amount from the receipt and output it in JSON format"},
            {"role": "user", "content": prompt},
        ]
    )

    analysis = response.choices[0].message['content']

    print('analysis', analysis)

    # JSON 포맷의 시작과 끝을 제거하고, 문자열을 정리하여 리턴
    cleaned_analysis = analysis.strip("```json").strip("```")

    return cleaned_analysis

def main():
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

                            # purchase_date가 YYYY-MM-DD 형식이면 YYMMDD 형식으로 변환
                            if purchase_date != 'N/A' and '-' in purchase_date:
                                try:
                                    # YYYY-MM-DD 형식으로 파싱
                                    parsed_date = datetime.strptime(purchase_date, "%Y-%m-%d")
                                    # YYMMDD 형식으로 변환
                                    purchase_date = parsed_date.strftime("%y%m%d")
                                except ValueError:
                                    # 예상치 못한 날짜 형식일 경우 그대로 유지
                                    pass

                            store_name = analysis_dict.get('store_name', 'N/A')
                            total_amount = analysis_dict.get('total_amount', 'N/A')
                            coffee = analysis_dict.get('coffee', 'N/A')

                            st.session_state["result"].append({
                                "fileId": img_file.file_id,
                                "fileName": img_file.name,
                                "purchase_date": purchase_date,
                                "store_name": store_name,
                                "total_amount": total_amount,
                                "coffee": coffee,
                            })

                            st.session_state.analysis_done = True
                            
                        except json.JSONDecodeError:
                            st.error("Failed to decode analysis result. Please check the format.")
                else:
                    st.error(f"OCR request failed: {img_file.name}")


    if st.session_state.analysis_done:
        for _, output in enumerate(st.session_state["result"]):
            st.write(output["fileName"])

            # if output["coffee"] == True:
            st.code(f"간식비_{output['total_amount']}_{output['purchase_date']}_서비스운영본부", language="python")
            # else:
            #     st.code(f"식비_점심_{output['total_amount']}_{output['purchase_date']}_김재익", language="python")

            st.code(str(output["total_amount"]))
            st.code(output["store_name"])

if __name__ == "__main__":
    main()