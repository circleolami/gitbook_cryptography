# 고전암호 (치환 암호, 전치 암호, 고전 암호 공격)

암호는 정보를 이해할 수 없도록 암호화하거나 다시 해독하기 위한 일련의 단계를 정리한 알고리즘입니다.&#x20;

## 치환 암호

치환 암호(Substitution Cipher)는 일정한 법칙에 따라 평문의 각 문자를 다른 문자로 치환하는 암호화 방식입니다. 크게 단일 문자 치환 암호와 다중 문자 치환 암호로 나눌 수 있습니다.&#x20;

1. 단일 문자 치환 암호

가장 단순한 형태의 치환 암호로, 알파벳의 각 문자를 다른 문자로 일대일 대응시켜 치환합니다. 그 예시로 카이사르 암호(Caesar Cipher)가 있습니다.&#x20;

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption><p>카이사르 암호(Caesar Cipher) </p></figcaption></figure>

2. 다중 문자 치환 암호&#x20;

평문의 문자 블록을 다른 문자 블록으로 치환하는 암호로, 한 글자씩 치환하는 단일 문자 치환보다 복잡하고 해독하기 어렵습니다. 그 예시로 폴리비우스 사각형(Polyblus Wquare)이 있습니다.&#x20;

<figure><img src=".gitbook/assets/image (1).png" alt=""><figcaption><p>폴리비우스 사각형(Polybius Square)</p></figcaption></figure>



## 전치 암호

전치 암호(Transposition Cipher)는 문자를 치환하는 치환 암호와 달리, 평문 위치를 재배치하는 암호화 방식입니다.&#x20;

1. 단순 전치 암호&#x20;

평문의 문자를 일정한 규칙에 따라 위치를 변경합니다. 예를 들어 아래 그림과 같이 열 단위로 문자를 재배열할 수 있습니다.&#x20;

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p>단순 전치 암호</p></figcaption></figure>

2. 스키테일 암호

고대 그리스에서 사용된 암호로, 긴 테이프를 원통에 감고 그 위에 메시지를 쓴 후 원통을 제거하여 문자의 순서를 변경합니다.&#x20;

<figure><img src=".gitbook/assets/image (3).png" alt=""><figcaption><p>스키테일 암호</p></figcaption></figure>



## 고전 암호 공격

고전 암호는 현대 암호에 비해 해독하기 쉽다고 알려져 있습니다. 기본적인 공격 방법은 다음과 같습니다. &#x20;

1. 전수 키 탐색 공격(Brute Force Attack)

가능한 모든 키를 시도하여 올바른 키를 찾아내는 방법으로, 키의 수가 적은 카이사르 암호가 전수 키 탐색 공격에 취약합니다.  &#x20;

<figure><img src=".gitbook/assets/image (4).png" alt=""><figcaption><p>Brute Force Attack</p></figcaption></figure>

2. 빈도 수 분석(Frequency Analysis)

언어의 특정 문자가 등장하는 빈도를 분석해서 암호를 해독하는 방법입니다. 예를 들어 영어에서 'E'는 가장 자주 사용되는 문자이므로, 암호문에서 가장 많이 등장하는 문자가 'E'일 가능성이 높다는 것을 이용합니다 다중 문자 치환 암호는 빈도 수 분석에 비교적 강합니다.&#x20;

<figure><img src=".gitbook/assets/image (5).png" alt=""><figcaption><p>알파벳 별 빈도 수</p></figcaption></figure>
