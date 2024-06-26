## Melhorias futuras

- SYN SCAN: Salvar o checksun do IP Header e o IP Header em um buffer para reutilizar em requisições seguidas, não sendo necessário calcular várias vezes. Uma outra alternativa é dividir em duas funções, uma monta os headers em structs, a principal faz o scan utilizando.
- TODOS: Verificar além de portas abertas e fechadas, as portas filtradas por firewall.
- Aceitar flag -h e --help oferecendo um help
- Aceitar escolher quais portas quer verificar
- Implementar --top-ports
- Identificar quais os serviços padrões das portas encontradas
- 