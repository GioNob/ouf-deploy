import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import it.comune.trieste.ouf.authorization.AuthorizationPolicy.GrantConstraints;

/** Real pinned owner DTO/Jackson: preserve the catalogue, round-trip constraints. */
public final class OwnerConstraintRoundTrip {
  public static void main(String[] args) throws Exception {
    var mapper=new ObjectMapper();
    var root=mapper.readTree(System.in);
    for(var role:root.path("roles")) for(var permission:role.path("permissions")) {
      var constraints=permission.get("constraints");
      if(constraints!=null && !constraints.isNull()) {
        var actual=mapper.treeToValue(constraints,GrantConstraints.class);
        ((ObjectNode)permission).set("constraints",mapper.valueToTree(actual));
      }
    }
    mapper.writeValue(System.out,root);
  }
}
