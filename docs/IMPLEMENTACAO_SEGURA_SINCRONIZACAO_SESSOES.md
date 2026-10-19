# Implementação segura da sincronização de sessões Zimbra/Keycloak

## 1. Objetivo

Melhorar o plugin `zm-sso` para sincronizar o ciclo de vida das sessões do Zimbra com o Keycloak, sem modificar o código-fonte do Zimbra e sem criar um serviço externo.

A implementação deverá fornecer:

1. Back-channel logout OIDC explícito e validado.
2. Heartbeat de sessão acionado pelo Webmail.
3. Renovação silenciosa por refresh token.
4. Monitoramento da validade da sessão OIDC pelo `zm-sso`.
5. Invalidação da sessão Zimbra quando a sessão Keycloak deixar de ser válida.
6. Heartbeat somente quando a aba estiver visível e houver atividade dentro de uma tolerância longa.
7. Respeito obrigatório aos limites máximos do Keycloak.
8. Encerramento de sessões abandonadas.
9. Suporte seguro a múltiplas abas.
10. Nenhuma utilização de `offline_access`.

## 2. Regras obrigatórias

Não execute todas as fases de uma só vez.

Ao receber esta instrução:

1. Execute somente a Fase 0.
2. Apresente os resultados.
3. Pare e aguarde aprovação.
4. Depois, execute uma fase por vez.
5. Nunca implante em produção ou reinicie o mailboxd sem autorização explícita.

Regras adicionais:

- Não modificar classes ou arquivos internos do Zimbra.
- Não modificar diretamente o Webmail do Zimbra.
- Não editar `web.xml`, arquivos do Jetty ou JARs nativos do Zimbra.
- Não presumir assinaturas de APIs do pac4j ou do Zimbra: confirmar nos JARs efetivamente instalados.
- Não registrar access tokens, refresh tokens, ID tokens, cookies, client secret ou logout tokens em logs.
- Não utilizar refresh token em JavaScript.
- Não implementar validação criptográfica manual de JWT se o pac4j já oferecer essa validação.
- Não invalidar todas as sessões de uma conta como solução padrão.
- Não usar `zimbraAuthTokenValidityValue` para logout individual sem aprovação expressa.
- Toda funcionalidade nova deve possuir feature flag e vir desabilitada por padrão.
- Preservar o login e logout atuais enquanto a nova funcionalidade estiver desabilitada.
- Antes de alterar banco, configuração ou empacotamento, produzir backup e plano de reversão.
- Se o projeto estiver em Git, trabalhar em branch separada. Não inicializar um novo repositório caso não exista.
- Não atualizar dependências sem primeiro verificar compatibilidade.

## 2.1. Reversibilidade obrigatória em produção

Todas as alterações serão realizadas diretamente em produção. Por esse motivo, a reversibilidade é um requisito obrigatório de projeto, e não apenas uma recomendação operacional.

Devem existir dois níveis independentes de reversão:

1. **Reversão de cada fase:** toda implementação, configuração, migração, endpoint, Zimlet ou alteração de dependência introduzida em uma fase deve poder ser desfeita isoladamente, restaurando exatamente o estado existente antes daquela fase, sem depender da conclusão das fases posteriores.
2. **Reversão integral:** a implementação completa deve poder ser removida, restaurando o ambiente ao estado atual anterior ao início deste trabalho, incluindo JARs, configurações, URLs do Keycloak, Zimlets, banco de dados, dependências e comportamento de login/logout.

Antes de iniciar qualquer fase que produza mudança, o executor deverá obrigatoriamente:

- Registrar o estado anterior de todos os arquivos, pacotes, configurações e componentes afetados.
- Criar cópias de segurança identificadas por data, fase, versão e checksum.
- Documentar os comandos exatos de aplicação e de reversão.
- Definir como confirmar que a reversão funcionou.
- Confirmar que os artefatos de rollback estão íntegros e acessíveis.
- Avaliar se a reversão exige reinício, nova autenticação dos usuários ou interrupção de sessões.
- Informar explicitamente o impacto esperado antes de executar a mudança.
- Não iniciar a alteração se o procedimento de rollback daquela fase estiver incompleto, não testável ou depender de um artefato inexistente.

Requisitos adicionais:

- Feature flags devem permitir desligar separadamente back-channel explícito, heartbeat, Zimlet e watchdog.
- Alterações de banco devem ser aditivas e retrocompatíveis. A versão anterior do plugin deve continuar funcionando mesmo que novas colunas permaneçam no banco.
- Nenhuma fase deve remover ou sobrescrever definitivamente o JAR, configuração, pacote ou export anterior.
- Alterações no cliente Keycloak devem ser precedidas por export completo e validado da configuração atual.
- Atualizações de dependências devem preservar um conjunto completo dos JARs anteriores; não será permitido rollback parcial com versões misturadas do pac4j.
- O Zimlet anterior, ou sua ausência, deve poder ser restaurado sem depender de recompilar o Zimbra.
- Se uma fase alterar sessões existentes de forma irreversível, essa fase deve ser interrompida e submetida a aprovação específica antes da execução.
- A reversão deve priorizar desativação por feature flag; restauração de artefatos será o segundo nível de contingência.

Ao final de cada fase, o relatório deverá declarar explicitamente:

```text
Checkpoint anterior:
Artefatos de backup:
Procedimento de rollback da fase:
Validação pós-rollback:
Impacto sobre sessões existentes:
Rollback integral continua possível: SIM/NÃO
```

Se a resposta para `Rollback integral continua possível` for `NÃO`, não avançar e não aplicar a fase.

## 3. Arquitetura desejada

A solução deverá permanecer dividida em duas partes:

```text
Zimlet/hook do Webmail
    │
    │ POST same-origin
    ▼
/service/extension/oidc/session
    │
    ├── valida token Zimbra
    ├── recupera perfil pac4j
    ├── verifica sessão e limites
    ├── renova OIDC quando necessário
    └── invalida Zimbra se o Keycloak não aceitar a sessão

Keycloak
    │
    │ POST com logout_token assinado
    ▼
/service/extension/oidc/backchannel-logout
    │
    ├── valida pelo pac4j
    ├── identifica sid/sub
    └── invalida exatamente a sessão Zimbra correspondente
```

O Zimlet será somente um sensor de atividade e um gatilho. Toda decisão de segurança será realizada no servidor pelo `zm-sso`.

---

# Fase 0 — inventário somente leitura

Não altere arquivos nesta fase.

## 0.1. Confirmar versões instaladas

Identifique:

- Versão do Zimbra.
- Versão do Java.
- Versão do `zm-sso`.
- Todos os JARs pac4j instalados.
- Origem do pacote instalado: Maven, Ant, RPM ou outro.
- Versão do Keycloak.
- Se o ambiente possui um ou vários mailboxd/nós.
- Se existe afinidade de sessão no proxy/balanceador.
- Se os usuários utilizam Classic UI, Modern UI ou ambas.

Existe uma divergência conhecida no código-fonte:

- `pom.xml`: pac4j 5.8.0.
- `build.xml`: pac4j 5.7.10.

A versão efetivamente carregada pelo mailboxd deve ser comprovada. Não confiar apenas no repositório.

Verifique manifests e `pom.properties` dos JARs. Não substituir nenhum arquivo.

## 0.2. Coletar configuração do zm-sso

Examinar, com o segredo redigido:

```text
/opt/zimbra/conf/zm.sso.properties
```

Registrar:

- `sso.defaultClient`
- `sso.callbackUrl`
- `oidc.callbackUrl`
- `oidc.discoveryUri`
- `oidc.scope`
- `sso.saveInSession`
- `sso.multiProfile`
- `sso.renewSession`
- `sso.localLogout`
- `sso.destroySession`
- `sso.centralLogout`
- `sso.postLogoutURL`

Nunca exibir `oidc.secret`.

## 0.3. Coletar configuração do Keycloak

Registrar, sem segredos:

- Realm.
- Client ID.
- Client type.
- Valid redirect URIs.
- Web origins.
- Front-channel logout URL.
- Back-channel logout URL.
- Back-channel logout session required.
- SSO Session Idle.
- SSO Session Max.
- Client Session Idle.
- Client Session Max.
- Access Token Lifespan.
- Refresh token rotation/revogação.
- Reuse interval, caso exista.
- Algoritmo de assinatura.
- Escopos concedidos.
- Confirmar que `offline_access` está ausente.

## 0.4. Confirmar o logout atualmente recebido

Nos logs existentes, verificar se o endpoint recebe:

- GET com `sid`/`iss`: provavelmente front-channel.
- POST com `logout_token`: back-channel OIDC real.

Não registrar o conteúdo integral do `logout_token`. Registrar apenas:

- Método HTTP.
- Endpoint.
- Content-Type.
- Existência ou ausência do parâmetro.
- Resultado HTTP.
- Timestamp.
- Hash curto para correlação, se necessário.

## 0.5. Confirmar APIs disponíveis

Inspecionar os JARs instalados e confirmar as assinaturas exatas de:

- `ProfileManager`
- `OidcClient`
- `OidcProfile`
- Renovação de perfil/token.
- `DefaultLogoutHandler`
- Store utilizado pelo logout handler.
- `AuthToken`
- `AuthTokenRegistry`
- Método de desregistro individual de um token Zimbra.
- Identificador estável de um `AuthToken`.

Não escrever código baseado em métodos encontrados apenas na documentação da versão mais recente.

## 0.6. Entrega da Fase 0

Produzir uma tabela:

```text
Componente | Versão instalada | Evidência | Observação
```

Produzir também:

- Configuração de timeout atual.
- Tipo real de logout recebido.
- Interfaces Webmail utilizadas.
- Topologia do ambiente.
- APIs confirmadas para refresh e revogação individual.
- Riscos encontrados.

Pare ao final da Fase 0.

---

# Fase 1 — desenho fechado e parâmetros

Somente iniciar após aprovação da Fase 0.

Nesta fase, ainda não alterar produção.

## 1.1. Definir a versão do pac4j

Se estiver instalada a versão 5.7.10:

- Não misturar JARs 5.7.10 e 5.8.0.
- Avaliar atualização conjunta de todos os módulos pac4j para uma versão compatível.
- Confirmar dependências transitivas.
- Validar em build e homologação.
- Não copiar somente `pac4j-oidc`.

A atualização deve ser tratada separadamente da funcionalidade de heartbeat.

## 1.2. Calcular intervalos

Definir:

- `H`: intervalo do heartbeat.
- `A`: duração do access token.
- `K`: Client Session Idle do Keycloak.
- `G`: tolerância após a última atividade humana.
- `M`: limite máximo absoluto.
- `R`: antecedência para refresh.

Deve ser atendida a relação:

```text
A - R + H < K
```

Isso assegura que uma tentativa de refresh ocorra antes do idle timeout do Keycloak.

Importante: o tempo total até uma sessão abandonada expirar será aproximadamente:

```text
G + K + H
```

Isso acontece porque o Zimlet continua enviando heartbeats durante `G`, e somente depois começa a contar o idle do Keycloak.

Portanto, se a política desejar expiração total após `T` minutos sem atividade:

```text
G deve ser menor ou igual a T - K - H
```

Exemplo apenas ilustrativo:

```text
Access token:             5 minutos
Heartbeat:                1 minuto
Client Session Idle:     30 minutos
Tolerância de atividade: 25 minutos
Expiração efetiva:       aproximadamente 56 minutos
Limite máximo:            definido pelo Keycloak
```

Não utilizar esses números sem confrontá-los com a política real.

## 1.3. Definir estados de sessão

Implementar uma máquina de estados simples:

```text
ACTIVE_VALID
RENEWING
TRANSIENT_ERROR
LOCALLY_IDLE
REVOKED
EXPIRED_MAX
LOGGED_OUT
```

Uma sessão `REVOKED`, `EXPIRED_MAX` ou `LOGGED_OUT` nunca pode voltar para `ACTIVE_VALID` sem nova autenticação completa.

## 1.4. Entrega da Fase 1

Documentar:

- Versão de pac4j escolhida.
- Valores propostos.
- Fórmula de expiração.
- Estratégia de cluster.
- Método confirmado de revogação individual do token Zimbra.
- Estratégia Classic/Modern UI.

Pare e aguarde aprovação.

---

# Fase 2 — configuração e estrutura sem mudança comportamental

Criar apenas a estrutura, mantendo tudo desabilitado.

## 2.1. Propriedades sugeridas

Adicionar ao arquivo de exemplo e ao carregamento de configurações:

```properties
oidc.sessionSync.enabled=false
oidc.sessionSync.backchannelEnabled=false

oidc.sessionSync.heartbeatIntervalSeconds=60
oidc.sessionSync.minimumServerIntervalSeconds=30
oidc.sessionSync.activityGraceSeconds=1500
oidc.sessionSync.hiddenTabGraceSeconds=120
oidc.sessionSync.refreshBeforeExpirySeconds=60

oidc.sessionSync.transientFailureGraceSeconds=180
oidc.sessionSync.maxTransientFailures=3
oidc.sessionSync.failClosed=true

oidc.sessionSync.absoluteMaxSeconds=0
oidc.sessionSync.allowedOrigin=https://mail.exemplo.gov.br

oidc.sessionSync.watchdogEnabled=false
oidc.sessionSync.watchdogIntervalSeconds=60
oidc.sessionSync.watchdogBatchSize=100
```

`absoluteMaxSeconds=0` não deverá significar ilimitado. Deve significar “usar o limite obtido/definido no Keycloak ou exigir configuração antes de habilitar”.

Arquivos esperados:

- `SettingsConstants.java`
- `ConfigBuilder.java`
- `conf/zm.sso.properties`
- Documentação das propriedades.

## 2.2. Validações

Na inicialização:

- Rejeitar valores negativos.
- Rejeitar heartbeat menor que o mínimo seguro.
- Rejeitar `allowedOrigin` vazio quando o recurso estiver habilitado.
- Emitir erro claro se `sessionSync` estiver habilitado sem OIDC.
- Não imprimir segredos.
- Não iniciar threads ou handlers ativos enquanto a feature flag estiver desligada.

## 2.3. Testes

Adicionar testes para:

- Defaults desabilitados.
- Parsing válido.
- Valores inválidos.
- Ausência de regressão no login atual.

Pare ao final da fase.

---

# Fase 3 — back-channel logout explícito

## 3.1. Novo endpoint

Criar um handler dedicado, por exemplo:

```text
/service/extension/oidc/backchannel-logout
```

Nome sugerido:

```text
OidcBackchannelLogoutHandler
```

Registrar em `ZmSsoExtension` somente quando:

```properties
oidc.sessionSync.backchannelEnabled=true
```

O endpoint deve aceitar somente o método exigido pelo OIDC Back-Channel Logout, normalmente `POST` com:

```text
Content-Type: application/x-www-form-urlencoded
logout_token=...
```

## 3.2. Validação do logout token

Delegar a validação ao pac4j sempre que a versão instalada oferecer suporte adequado.

Devem ser validados:

- Assinatura.
- Emissor.
- Audiência/client ID.
- Algoritmo permitido.
- Expiração/tempo de emissão.
- Claim `events` de back-channel logout.
- `sid` ou `sub`.
- Ausência de `nonce`, conforme especificação aplicável.
- Replay, preferencialmente por `jti`.

Não criar um parser JWT que apenas decodifique Base64. Decodificar não é validar.

## 3.3. Mapeamento por sessão

No login/callback, registrar de maneira segura:

- Hash do `sid` OIDC.
- Identificador da conta.
- Instante inicial.
- Identificador da sessão pac4j.
- Identificador revogável do token Zimbra, se a API suportar.
- Status.

Não armazenar:

- Refresh token.
- Access token.
- ID token.
- `ZM_AUTH_TOKEN` codificado.
- `logout_token`.

Se for necessário alterar a tabela existente:

- Usar colunas novas e anuláveis.
- Criar migração idempotente.
- Não remover colunas.
- Criar índice no hash do `sid`.
- Preparar rollback de aplicação sem exigir rollback destrutivo do schema.

## 3.4. Invalidação local

Criar uma operação centralizada e idempotente, por exemplo:

```text
invalidateLocalSession(sessionReference, reason)
```

Ela deverá:

1. Marcar a sessão como revogada/logout.
2. Impedir novos heartbeats.
3. Desregistrar somente o token Zimbra associado.
4. Invalidar/remover a sessão pac4j correspondente.
5. Registrar auditoria sem tokens.
6. Tolerar chamadas repetidas.

No back-channel não existe navegador para limpar o cookie. Portanto, desregistrar o token no servidor é obrigatório.

Não usar o incremento de `zimbraAuthTokenValidityValue` como comportamento padrão, pois isso pode invalidar todas as sessões da conta.

Se não for possível revogar somente um token:

- Pare.
- Documente a limitação.
- Não implemente silenciosamente a invalidação global.
- Solicite decisão explícita entre invalidação ampla, filtro de requisições ou outra estratégia.

## 3.5. Testes obrigatórios

- Logout token válido.
- Assinatura inválida.
- Emissor inválido.
- Audiência inválida.
- Token expirado.
- `events` ausente/incorreto.
- Replay do mesmo `jti`.
- `sid` desconhecido.
- Logout repetido.
- Duas sessões da mesma conta.
- Logout de uma sessão sem afetar a outra.
- Logout administrativo no Keycloak.
- Logout pelo Account Console.

Pare ao final da fase.

---

# Fase 4 — endpoint de heartbeat no zm-sso

## 4.1. Novo handler

Criar:

```text
POST /service/extension/oidc/session
```

Nome sugerido:

```text
OidcSessionHandler
```

Não oferecer versão GET.

O endpoint deve usar:

```text
request.getSession(false)
```

Ele não deve criar uma sessão HTTP nova quando a sessão anterior não existir.

## 4.2. Proteção da requisição

Preferir o mecanismo CSRF nativo do Zimbra, se estiver disponível e puder ser utilizado pelo Zimlet.

Se isso não for possível, exigir em conjunto:

- `Origin` exatamente igual ao host configurado.
- `Sec-Fetch-Site: same-origin`, quando enviado pelo navegador.
- Header customizado, por exemplo:

```text
X-Zm-Sso-Heartbeat: 1
```

- `Content-Type: application/json`.
- Ausência de CORS permissivo.
- Nunca utilizar `Access-Control-Allow-Origin: *`.
- Cookie `Secure`.
- Cookie `HttpOnly` para credenciais.
- `SameSite` compatível com o fluxo OIDC.

## 4.3. Validação do token Zimbra

Antes de consultar o pac4j:

1. Recuperar o token com a API nativa do Zimbra.
2. Confirmar que existe.
3. Confirmar que não expirou.
4. Confirmar que está registrado.
5. Recuperar a conta.
6. Comparar a conta com o perfil OIDC.

Se o token for inválido, retornar `401` sem criar sessão nova.

## 4.4. Recuperação do perfil OIDC

Recuperar a sessão pac4j existente e obter especificamente um `OidcProfile`.

Validar:

- Client correto.
- Issuer esperado.
- Subject presente.
- E-mail/identificador compatível com a conta Zimbra.
- `sid` compatível com o mapeamento criado no login.
- `auth_time` ou instante inicial conhecido.
- Limite máximo ainda não ultrapassado.

A comparação entre conta Zimbra e perfil OIDC deve ser normalizada com cuidado, mas não deve permitir mudança de identidade após o login.

## 4.5. Renovação

Não chamar o Keycloak em todo heartbeat.

Se o access token ainda for válido além de `refreshBeforeExpirySeconds`:

- Retornar sucesso local.
- Atualizar somente o instante do heartbeat.
- Não realizar refresh.

Se estiver próximo da expiração:

1. Adquirir uma trava por sessão, nunca uma trava global.
2. Verificar novamente se outra aba já renovou.
3. Executar o método de renovação confirmado na Fase 0.
4. Persistir imediatamente o perfil atualizado na sessão pac4j.
5. Garantir que um refresh token rotacionado substituiu o anterior.
6. Liberar a trava.
7. Retornar `204`.

Nunca expor os tokens na resposta.

## 4.6. Classificação dos erros

### Erros definitivos

Exemplos:

- `invalid_grant`
- Refresh token expirado
- Refresh token revogado
- Sessão inexistente
- Conta divergente
- Limite máximo ultrapassado
- Sessão marcada como revogada

Ação:

1. Invalidar a sessão local.
2. Limpar o cookie Zimbra na resposta, quando possível.
3. Retornar `401`.
4. Não tentar novamente com o mesmo refresh token.

### Erros transitórios

Exemplos:

- Timeout
- DNS
- Conexão recusada
- HTTP 502/503/504

Ação:

1. Não classificar como revogação.
2. Incrementar contador por sessão.
3. Retornar `503` com `Retry-After`.
4. Respeitar `transientFailureGraceSeconds`.
5. Após ultrapassar a tolerância configurada, aplicar `failClosed`.

Uma falha transitória nunca deve renovar artificialmente o limite máximo.

## 4.7. Códigos de resposta

Usar semântica previsível:

```text
204  sessão válida
401  sessão inválida, revogada ou expirada
403  origem/CSRF/identidade incompatível
409  renovação já em curso, se realmente necessário
429  heartbeat excessivo
503  falha temporária do Keycloak
```

Não devolver stack trace ao navegador.

## 4.8. Testes obrigatórios

- Token Zimbra válido e access token ainda válido.
- Renovação bem-sucedida.
- Refresh token rotacionado.
- `invalid_grant`.
- Sessão Keycloak revogada.
- Limite máximo ultrapassado.
- Conta Zimbra diferente do perfil.
- Ausência de sessão HTTP.
- Origin incorreto.
- Ausência do header customizado.
- Heartbeats excessivos.
- Timeout do Keycloak.
- Tolerância transitória esgotada.
- Dez chamadas concorrentes da mesma sessão.
- Duas sessões diferentes da mesma conta.

Pare ao final da fase.

---

# Fase 5 — Zimlet/hook do Webmail

Primeiro confirmar se será necessário um artefato para Classic UI, Modern UI ou ambos.

Não alterar diretamente arquivos internos do Webmail.

## 5.1. Atividade monitorada

Considerar atividade:

- `pointerdown`
- `keydown`
- `touchstart`
- navegação interna relevante
- retorno de foco/visibilidade

Evitar usar `mousemove` sem throttling, pois ele gera eventos em excesso.

Guardar apenas timestamps, nunca dados digitados.

## 5.2. Regra de envio

Enviar heartbeat somente quando:

```text
document.visibilityState === "visible"
```

e:

```text
agora - ultimaAtividade <= activityGraceSeconds
```

Quando a aba ficar oculta:

- Permitir somente `hiddenTabGraceSeconds`.
- Depois interromper o heartbeat.
- Não fazer logout ao fechar a página.
- Não usar `beforeunload` como mecanismo de segurança.

Ao voltar para uma aba oculta ou localmente inativa:

1. Exibir temporariamente um estado “validando sessão”.
2. Chamar imediatamente o endpoint.
3. Somente liberar interações sensíveis após `204`.
4. Em `401`, redirecionar uma única vez para o login.
5. Em `503`, aplicar a política de tolerância e mostrar mensagem discreta.

Isso evita que a primeira ação após horas de abandono seja executada antes da validação.

## 5.3. Múltiplas abas

Implementar eleição de uma aba líder com:

- `BroadcastChannel`, preferencialmente.
- `localStorage` como fallback.

A liderança deve usar lease com expiração. Se a aba líder for fechada, outra assume.

Somente a líder envia o heartbeat. As demais recebem o resultado e atualizam seu estado.

Não confiar apenas nessa coordenação: o servidor também deve possuir trava por sessão.

## 5.4. Chamada HTTP

Exemplo conceitual:

```javascript
fetch("/service/extension/oidc/session", {
  method: "POST",
  credentials: "same-origin",
  headers: {
    "Content-Type": "application/json",
    "X-Zm-Sso-Heartbeat": "1"
  },
  body: "{}"
});
```

Não copiar esse trecho sem adaptar ao mecanismo CSRF confirmado.

Usar `setTimeout` recursivo em vez de `setInterval`, porque navegadores suspendem e acumulam timers em abas inativas.

Adicionar pequeno jitter ao intervalo.

## 5.5. Tratamento das respostas

- `204`: atualizar o instante da última validação.
- `401`: bloquear a interface, encerrar heartbeat e redirecionar uma vez.
- `403`: bloquear e registrar erro de segurança sem repetir.
- `429`: respeitar `Retry-After`.
- `503`: aguardar e tentar novamente dentro da tolerância.
- Falha de rede: tratar como transitória, não como refresh revogado.

## 5.6. Testes obrigatórios

- Aba visível e ativa.
- Usuário apenas lendo dentro da tolerância.
- Tolerância ultrapassada.
- Aba oculta.
- Fechamento da aba.
- Retorno após expiração no Keycloak.
- Suspensão e retomada do notebook.
- Navegador offline e retorno online.
- Múltiplas abas.
- Restauração automática de abas pelo navegador.
- Classic UI.
- Modern UI.
- Chrome/Chromium e Firefox suportados institucionalmente.

Pare ao final da fase.

---

# Fase 6 — monitoramento de sessões abandonadas pelo servidor

Esta fase é necessária se o requisito for impedir que um token Zimbra abandonado continue utilizável até sua expiração nativa.

O watchdog deve apenas encerrar sessões antigas. Ele nunca deve renovar tokens.

## 6.1. Condição obrigatória

Somente implementar se a Fase 0 comprovou uma forma segura de invalidar um token Zimbra individual.

Se apenas a invalidação de toda a conta estiver disponível, pare e solicite decisão.

## 6.2. Funcionamento

O `zm-sso` deverá registrar o último heartbeat válido.

Periodicamente, localizar sessões que satisfaçam:

```text
status = ACTIVE_VALID
e
lastHeartbeatAt + limiteCalculado < agora
```

O limite deve considerar:

- Activity grace.
- Keycloak Client Session Idle.
- Intervalo do heartbeat.
- Margem de relógio.
- Tolerância de falhas transitórias.

Para cada sessão vencida:

1. Fazer atualização condicional/atômica do status.
2. Invalidar somente o token Zimbra correspondente.
3. Remover a sessão pac4j.
4. Registrar o motivo `HEARTBEAT_TIMEOUT`.
5. Não chamar refresh token.
6. Não afetar outras sessões da conta.

## 6.3. Cluster

Em múltiplos nós:

- Usar lock distribuído ou eleição simples via banco.
- Processar em lotes limitados.
- Tornar a operação idempotente.
- Impedir que dois nós invalidem a mesma sessão simultaneamente.
- Não criar uma thread sem encerrá-la em `ZmSsoExtension.destroy()`.

## 6.4. Alternativa se o watchdog não for seguro

Se não houver revogação individual confiável, implementar inicialmente apenas:

- Back-channel explícito.
- Heartbeat.
- Validação obrigatória no retorno da aba.
- Timeouts Zimbra alinhados.

Documentar que a garantia será “bloqueio na próxima interação”, não revogação instantânea após idle.

Pare ao final da fase.

---

# Fase 7 — observabilidade e auditoria

Registrar eventos estruturados:

```text
SESSION_CREATED
HEARTBEAT_ACCEPTED
TOKEN_REFRESHED
TRANSIENT_PROVIDER_FAILURE
SESSION_REVOKED
BACKCHANNEL_LOGOUT
ABSOLUTE_MAX_REACHED
HEARTBEAT_TIMEOUT
LOCAL_TOKEN_INVALIDATED
```

Campos permitidos:

- Timestamp.
- Node ID.
- Client ID.
- Account ID ou identificador administrativo permitido.
- Hash do `sid`.
- Hash da referência da sessão.
- Motivo.
- Resultado.
- Latência.
- Contagem de tentativas.

Campos proibidos:

- Access token.
- Refresh token.
- ID token.
- Client secret.
- Cookie.
- Logout token completo.
- Token Zimbra codificado.

Corrigir também o problema de `logoutAt == null` na consulta administrativa antes de utilizá-la para auditoria.

---

# Fase 8 — homologação

## 8.1. Preparação

- Exportar configuração anterior do cliente Keycloak.
- Copiar o JAR anterior do `zm-sso`.
- Salvar configuração anterior.
- Confirmar procedimento de restauração.
- Criar COS ou grupo piloto.
- Não habilitar globalmente.

## 8.2. Cenários mínimos

1. Login normal.
2. Uso ativo além do idle timeout anterior.
3. Leitura prolongada dentro da tolerância.
4. Aba oculta até o Keycloak expirar.
5. Retorno após expiração.
6. Logout pelo Webmail.
7. Logout pelo Keycloak.
8. Revogação administrativa.
9. Limite máximo atingido com uso contínuo.
10. Refresh token rotation.
11. Duas abas.
12. Dois navegadores para a mesma conta.
13. Falha temporária do Keycloak.
14. Keycloak indisponível além da tolerância.
15. Reinício de um nó.
16. Failover, caso exista cluster.
17. Sessões criadas antes da atualização.
18. Classic e Modern UI.
19. Carga com número representativo de sessões.
20. Confirmação de que logs não contêm tokens.

## 8.3. Critérios de aprovação

A solução só pode ser considerada pronta se:

- Sessão ativa renova silenciosamente.
- Sessão abandonada deixa de renovar.
- Limite máximo nunca é ultrapassado.
- Revogação administrativa bloqueia o Zimbra.
- Logout de uma sessão não derruba outras sessões da conta, salvo política explicitamente aprovada.
- Múltiplas abas não causam erros de rotação.
- Falha temporária não provoca logout em massa imediato.
- Nenhum token aparece em logs.
- O comportamento anterior permanece disponível com feature flag desligada.

---

# Fase 9 — implantação gradual

Ordem obrigatória:

1. Criar e validar o checkpoint completo do estado atual.
2. Confirmar o rollback específico da fase antes de aplicar qualquer artefato.
3. Instalar artefato com todas as features desligadas.
4. Confirmar login/logout anterior.
5. Habilitar logs sem tokens.
6. Habilitar back-channel apenas para grupo piloto.
7. Observar.
8. Habilitar endpoint de heartbeat para grupo piloto.
9. Habilitar Zimlet para a mesma população.
10. Observar pelo menos um ciclo completo de idle e limite máximo.
11. Habilitar watchdog somente após comprovar revogação individual.
12. Expandir por COS ou grupos.
13. Somente depois avaliar habilitação global.

Sessões anteriores à implantação podem não possuir `sid` ou associação completa. Não considerá-las sincronizadas silenciosamente. Escolher entre:

- Mantê-las no comportamento antigo até expirarem.
- Exigir uma nova autenticação controlada para o grupo piloto.

Não invalidar todas de uma vez sem aprovação.

---

# Plano de reversão

A reversão deve ser possível em camadas e deve restaurar tanto a fase imediatamente anterior quanto, se necessário, todo o ambiente ao estado atual anterior ao início da implementação.

Antes da primeira mudança, criar um checkpoint integral contendo:

- JAR e pacote atualmente instalados do `zm-sso`.
- Relação, versão e checksum de todos os JARs pac4j carregados.
- Cópia da configuração atual do `zm-sso`, protegendo os segredos.
- Export completo do cliente e das configurações relevantes do realm no Keycloak.
- Configurações efetivas do Zimbra e da COS envolvida.
- Estado de implantação e pacote do Zimlet, se existir.
- Versão do schema e backup lógico das tabelas modificadas pelo plugin.
- Procedimento de reinício e validação conhecido para o mailboxd.
- Evidências do funcionamento atual de login, callback e logout.

A cada fase, criar um novo checkpoint incremental. Não reutilizar ou sobrescrever o checkpoint inicial.

Sequência de reversão em camadas:

1. Desabilitar watchdog.
2. Desabilitar Zimlet.
3. Desabilitar heartbeat.
4. Restaurar URL de back-channel anterior.
5. Desabilitar back-channel explícito.
6. Restaurar JAR anterior.
7. Restaurar configuração anterior.
8. Reiniciar mailboxd somente em janela aprovada.
9. Restaurar export do cliente Keycloak se necessário.

O schema de banco deverá ser aditivo, permitindo que o JAR anterior ignore as novas colunas. Não remover dados durante rollback.

Após qualquer rollback, validar obrigatoriamente:

1. Carregamento do mailboxd e do plugin sem erros.
2. Login OIDC no fluxo atualmente utilizado.
3. Callback OIDC.
4. Acesso ao Webmail com o token Zimbra.
5. Logout existente.
6. Ausência de chamadas ao endpoint ou Zimlet desabilitado que foi revertido.
7. Ausência de mistura de versões dos JARs pac4j.
8. Situação das sessões que existiam antes da reversão.

Se a reversão de uma fase não restaurar o comportamento anterior, executar a reversão integral usando o checkpoint inicial e interromper a implantação.

---

# Resultado esperado de cada fase

Ao terminar cada fase, responder apenas com:

1. O que foi examinado ou alterado.
2. Arquivos envolvidos.
3. Diff resumido.
4. Testes executados e resultados.
5. Riscos ou dúvidas restantes.
6. Como reverter aquela fase.
7. Se os critérios de aceite foram atendidos.
8. Pedido explícito de autorização para a próxima fase.
9. Checkpoint criado antes da fase.
10. Procedimento exato para reverter somente aquela fase.
11. Confirmação de que a reversão integral para o estado inicial continua disponível.

Não avançar automaticamente.

---

## Observação crítica: heartbeat não é refresh

O heartbeat pode ocorrer a cada minuto, mas a chamada ao token endpoint do Keycloak deve ocorrer apenas quando o access token estiver próximo da expiração.

Isso reduz carga, preserva a rotação correta do refresh token e mantém o `Client Session Idle` ativo sem transformar cada evento do navegador em uma chamada ao Keycloak.
