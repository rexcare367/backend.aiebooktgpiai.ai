from fastapi import APIRouter, Request, Response, Depends
import re
import json
from datetime import datetime
from openai import OpenAI
from sqlalchemy.orm import Session
from database.connection import get_db
from database.models import Books, Quiz, User

client = OpenAI()

router = APIRouter(
    prefix="/api/ebooks",
    tags=["quizzes"],
)

@router.post("/generate-quiz")
async def generate_quiz(request: Request, db: Session = Depends(get_db)):
    try:
        data = await request.json()
        book_id = data.get('book_id')
        user_ic = data.get('user_ic')

        user = db.query(User).filter(User.ic_number == user_ic).first()

        book = db.query(Books).filter(Books.id == book_id).first()
        
        assistantId = book.assistant_id
        thread = client.beta.threads.create()
        threadId = thread.id

        res_message=""

        client.beta.threads.messages.create(
            thread_id=threadId,
            role="user",
            content=[
                    {
                        "type": "text",
                        "text": f"""
                           I'm building a book reading website and need to generate quizzes based on the book's content embedded on this assistant. 
                            Generate exactly 3 quizzes based on the book content. final respose must follow this exact JSON format:
                            ```json
                            [
                                <
                                    "question": "xxx",
                                    "answer": [
                                        <"text": "aaa", "correct": false>,
                                        <"text": "bbb", "correct": true>,
                                        <"text": "ccc", "correct": false>
                                    ]
                                >,
                                <
                                    "question": "xxx",
                                    "answer": [
                                        <"text": "aaa", "correct": false>,
                                        <"text": "bbb", "correct": true>,
                                        <"text": "ccc", "correct": false>
                                    ]
                                >,
                                <
                                    "question": "xxx",
                                    "answer": [
                                        <"text": "aaa", "correct": false>,
                                        <"text": "bbb", "correct": true>,
                                        <"text": "ccc", "correct": false>
                                    ]
                                >
                            ]
                            ```

                        """
                    },
            ],
        )

        run = client.beta.threads.runs.create_and_poll(
            thread_id=threadId,
            assistant_id=assistantId,
            instructions="Please answer the question simpler same language with associated file"
        )

        if run.status == 'completed':
            print("Run completed successfully. Processing messages.")
            messages = client.beta.threads.messages.list(thread_id=run.thread_id, run_id=run.id)
            print("messages", messages)
            for msg in messages.data:
                if msg.role == "assistant":
                    for content_item in msg.content: 
                        if content_item.type == 'text':
                            text_value = content_item.text.value
                            res_message=text_value
                            response = f"Assistant says: {text_value}"
                        else:
                            response = "Assistant says: Unhandled content type."
                else:
                    response = f"User says: {msg.content}"
                    print(f"Processing user message: {response}")

        # Extract JSON objects from the answer_text and add them to quiz_list
        pattern = r'```json(.*?)```'  # Define regex pattern to match code enclosed in ```
        matches = re.findall(pattern, res_message, re.DOTALL)  # Find all matches of the pattern
        quizzes = []

        _matches = json.loads(matches[0])

        for quiz_answer in _matches:
            print("quiz_answer", quiz_answer)

            if quiz_answer['question'] or quiz_answer['answer']:
                quiz = {"question": "", "answer": [], 'id': ''}

                # Create new quiz in database
                new_quiz = Quiz(
                    book_id=book.id,
                    user_id=user.id,
                    question=quiz_answer['question'],
                    answer=quiz_answer['answer']
                )
                db.add(new_quiz)
                db.commit()
                db.refresh(new_quiz)

                quiz['question'] = quiz_answer['question']
                quiz['id'] = new_quiz.id  # Add the quiz ID to the response

                for answer in quiz_answer['answer']:   
                    quiz['answer'].append(answer['text'])
            quizzes.append(quiz)
        return {"success": True, 'quizzes': quizzes}

    except Exception as e:
        print(f"Error while generating quiz: {e}")
        return {"success": False,  'quizzes': [], "data": 'Error while generating quiz'}

@router.post("/submit-answer")
async def answer_quiz(request: Request, db: Session = Depends(get_db)):
    data = await request.json()
    answers = data.get('answers')
    
    score = 0
    result = []

    for answer in answers:
        quiz_id = answer.get('quizId')
        user_answer_index = int(answer.get('answer'))

        quiz = db.query(Quiz).filter(Quiz.id == quiz_id).first()

        if quiz and quiz.answer[user_answer_index]["correct"] == 'True':
            result.append(True)
            score += 1
        else:
            result.append(False)
    
    return {"success": True, "score": score, "result": result}