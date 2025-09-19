from fastapi import FastAPI
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import re

app = FastAPI()


class Payload(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    code: str


class ResponseModel(BaseModel):
    pgm_name: str
    inc_name: str
    type: str
    name: Optional[str] = ""
    class_implementation: Optional[str] = ""
    original_code: str
    remediated_code: str


def process_abap_code(payload: Payload):
    code = payload.code
    original_code = code
    today_str = datetime.now().strftime("%Y-%m-%d")
    tag = f"\"Added By Pwc {today_str}"

    remediated_code = code

    # --- Case 1: Replace field references (j_1imocust-field or j_1imocust~field)
    pattern_cust_field = re.compile(r'\bj_1imocust([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_cust_field.sub(
        lambda m: f"kna1{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 2: Replace field references (j_1imovend-field or j_1imovend~field)
    pattern_vend_field = re.compile(r'\bj_1imovend([-~])([a-zA-Z_]\w*)', re.IGNORECASE)
    remediated_code = pattern_vend_field.sub(
        lambda m: f"lfa1{m.group(1)}{m.group(2)} {tag}", remediated_code
    )

    # --- Case 3: Replace standalone table/type references J_1IMOCUST
    pattern_cust_table = re.compile(r'\bj_1imocust\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_cust_table.sub(
        lambda m: f"KNA1 {tag}", remediated_code
    )

    # --- Case 4: Replace standalone table/type references J_1IMOVEND
    pattern_vend_table = re.compile(r'\bj_1imovend\b(?![-~])', re.IGNORECASE)
    remediated_code = pattern_vend_table.sub(
        lambda m: f"LFA1 {tag}", remediated_code
    )

    return ResponseModel(
        pgm_name=payload.pgm_name,
        inc_name=payload.inc_name,
        type=payload.type,
        name=payload.name,
        class_implementation=payload.class_implementation,
        original_code=original_code,
        remediated_code=remediated_code,
    )


@app.post('/remediate_abap', response_model=ResponseModel)
async def remediate_abap(payload: Payload):
    return process_abap_code(payload)
